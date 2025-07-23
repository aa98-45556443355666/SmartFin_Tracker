from sqlalchemy import create_engine, text
import os
from dotenv import load_dotenv
from werkzeug.security import check_password_hash
load_dotenv()

current_dir = os.path.dirname(os.path.abspath(__file__))
ca_bundle_path = os.path.join(current_dir, 'singlestore_bundle.pem')

engine = create_engine(
    os.environ.get('DB_CONNECTION_STR'),
    connect_args={
        "ssl": {
            "ca": ca_bundle_path
        },
        "charset": "utf8mb4"
    }
)


def get_user_by_email(email):
    with engine.connect() as conn:
        res = conn.execute(
            text("SELECT * FROM users WHERE email = :email"), {"email": email})
        row = res.fetchone()
        return row._asdict() if row else None


def add_user(name, email, password_hash):
    with engine.connect() as conn:
        try:
            conn.execute(
                text(
                    "INSERT INTO users (name, email, password) VALUES (:name, :email, :password)"),
                {"name": name, "email": email, "password": password_hash}
            )
            conn.commit()
            return True
        except Exception as e:
            print(f"Error adding user: {e}")
            conn.rollback()
            return False


def get_user_by_id(user_id):
    with engine.connect() as conn:
        res = conn.execute(
            text("SELECT * FROM users WHERE id = :id"), {"id": user_id})
        row = res.fetchone()
        return row._asdict() if row else None


def get_transactions(user_id, month=None, year=None, type_filter=None, search=None, limit=None):
    query = "SELECT * FROM transactions WHERE user_id = :user_id"
    params = {"user_id": user_id}
    if month:
        query += " AND MONTH(date) = :month"
        params["month"] = month
    if year:
        query += " AND YEAR(date) = :year"
        params["year"] = year
    if type_filter in ['income', 'expense']:
        query += " AND type = :type"
        params["type"] = type_filter
    if search:
        query += " AND (LOWER(description) LIKE :search OR LOWER(category) LIKE :search)"
        params["search"] = f"%{search.lower()}%"
    query += " ORDER BY date DESC"
    if limit:
        query += " LIMIT :limit"
        params["limit"] = limit
    with engine.connect() as conn:
        res = conn.execute(text(query), params)
        return [row._asdict() for row in res.fetchall()]


def add_transaction(user_id, amount, type_, category, description, date):
    with engine.connect() as conn:
        try:
            conn.execute(
                text("INSERT INTO transactions (user_id, amount, type, category, description, date) VALUES (:user_id, :amount, :type, :category, :description, :date)"),
                {"user_id": user_id, "amount": amount, "type": type_,
                    "category": category, "description": description, "date": date}
            )
            conn.commit()
            return True
        except Exception as e:
            print(f"Error adding transaction: {e}")
            conn.rollback()
            return False


def update_transaction(transaction_id, user_id, amount, type_, category, description, date):
    with engine.connect() as conn:
        try:
            conn.execute(
                text("UPDATE transactions SET amount=:amount, type=:type, category=:category, description=:description, date=:date WHERE id=:id AND user_id=:user_id"),
                {"id": transaction_id, "user_id": user_id, "amount": amount, "type": type_,
                    "category": category, "description": description, "date": date}
            )
            conn.commit()
            return True
        except Exception as e:
            print(f"Error updating transaction: {e}")
            conn.rollback()
            return False


def delete_transaction(transaction_id, user_id):
    with engine.connect() as conn:
        try:
            conn.execute(
                text("DELETE FROM transactions WHERE id=:id AND user_id=:user_id"),
                {"id": transaction_id, "user_id": user_id}
            )
            conn.commit()
            return True
        except Exception as e:
            print(f"Error deleting transaction: {e}")
            conn.rollback()
            return False


def get_goals(user_id):
    with engine.connect() as conn:
        res = conn.execute(
            text("SELECT * FROM goals WHERE user_id = :user_id"), {"user_id": user_id})
        return [row._asdict() for row in res.fetchall()]


def add_goal(user_id, name, target_amount, current_amount, target_date):
    with engine.connect() as conn:
        try:
            conn.execute(
                text("INSERT INTO goals (user_id, name, target_amount, current_amount, target_date) VALUES (:user_id, :name, :target_amount, :current_amount, :target_date)"),
                {"user_id": user_id, "name": name, "target_amount": target_amount,
                    "current_amount": current_amount, "target_date": target_date}
            )
            conn.commit()
            return True
        except Exception as e:
            print(f"Error adding goal: {e}")
            conn.rollback()
            return False


def update_goal(goal_id, user_id, name, target_amount, current_amount, target_date):
    with engine.connect() as conn:
        try:
            conn.execute(
                text("UPDATE goals SET name=:name, target_amount=:target_amount, current_amount=:current_amount, target_date=:target_date WHERE id=:id AND user_id=:user_id"),
                {"id": goal_id, "user_id": user_id, "name": name, "target_amount": target_amount,
                    "current_amount": current_amount, "target_date": target_date}
            )
            conn.commit()
            return True
        except Exception as e:
            print(f"Error updating goal: {e}")
            conn.rollback()
            return False


def delete_goal(goal_id, user_id):
    with engine.connect() as conn:
        try:
            conn.execute(
                text("DELETE FROM goals WHERE id=:id AND user_id=:user_id"),
                {"id": goal_id, "user_id": user_id}
            )
            conn.commit()
            return True
        except Exception as e:
            print(f"Error deleting goal: {e}")
            conn.rollback()
            return False


def add_funds_to_goal(goal_id, user_id, amount):
    with engine.connect() as conn:
        try:
            conn.execute(
                text(
                    "UPDATE goals SET current_amount = current_amount + :amount WHERE id=:id AND user_id=:user_id"),
                {"id": goal_id, "user_id": user_id, "amount": amount}
            )
            conn.commit()
            return True
        except Exception as e:
            print(f"Error adding funds: {e}")
            conn.rollback()
            return False


def get_goal_by_id(goal_id, user_id):
    with engine.connect() as conn:
        res = conn.execute(text(
            "SELECT * FROM goals WHERE id = :id AND user_id = :user_id"), {"id": goal_id, "user_id": user_id})
        row = res.fetchone()
        return row._asdict() if row else None


def get_transaction_by_id(transaction_id, user_id):
    with engine.connect() as conn:
        res = conn.execute(text("SELECT * FROM transactions WHERE id = :id AND user_id = :user_id"),
                           {"id": transaction_id, "user_id": user_id})
        row = res.fetchone()
        return row._asdict() if row else None


def get_income_expense_sum(user_id, month, year, type_):
    with engine.connect() as conn:
        res = conn.execute(
            text("SELECT SUM(amount) FROM transactions WHERE user_id=:user_id AND type=:type AND MONTH(date)=:month AND YEAR(date)=:year"),
            {"user_id": user_id, "type": type_, "month": month, "year": year}
        )
        total = res.scalar()
        return total or 0


def get_expense_categories(user_id, month, year):
    with engine.connect() as conn:
        res = conn.execute(
            text("SELECT category, SUM(amount) as total FROM transactions WHERE user_id=:user_id AND type='expense' AND MONTH(date)=:month AND YEAR(date)=:year GROUP BY category"),
            {"user_id": user_id, "month": month, "year": year}
        )
        return {row[0]: row[1] for row in res.fetchall()}
