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
    },
    pool_recycle=3600
)

def _execute_query(conn,query,params):
    return conn.execute(text(query), params)

def get_user_by_email(email):
    with engine.connect() as conn:
        res = _execute_query(conn,
            "SELECT * FROM users WHERE email = :email", {"email": email})
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
        res = _execute_query(conn,
            "SELECT * FROM users WHERE id = :id", {"id": user_id})
        row = res.fetchone()
        return row._asdict() if row else None

def get_transactions(conn, user_id, month=None, year=None, type_filter=None, category_filter=None, search=None, limit=None):
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
    if category_filter:
        query += " AND category = :category"
        params["category"] = category_filter
    if search:
        query += " AND (LOWER(description) LIKE :search OR LOWER(category) LIKE :search)"
        params["search"] = f"%{search.lower()}%"

    query += " ORDER BY date DESC"

    if limit:
        query += " LIMIT :limit"
        params["limit"] = limit

    res = _execute_query(conn, query, params)
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


def get_goals(conn,user_id):

    res = _execute_query(conn,
            "SELECT * FROM goals WHERE user_id = :user_id", {"user_id": user_id})
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


def get_income_expense_summary(conn, user_id, month, year):
    query = """
        SELECT
            SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) as income,
            SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) as expenses
        FROM transactions
        WHERE user_id = :user_id AND MONTH(date) = :month AND YEAR(date) = :year
    """
    params = {"user_id": user_id, "month": month, "year": year}
    res = _execute_query(conn, query, params)
    summary = res.fetchone()
    return (summary.income or 0, summary.expenses or 0)

def get_expense_categories(conn, user_id, month, year):
    query = """
        SELECT category, SUM(amount) as total 
        FROM transactions 
        WHERE user_id=:user_id AND type='expense' AND MONTH(date)=:month AND YEAR(date)=:year 
        GROUP BY category
    """
    params = {"user_id": user_id, "month": month, "year": year}
    res = _execute_query(conn, query, params)
    return {row[0]: row[1] for row in res.fetchall()}