from flask import Flask, render_template, redirect, url_for, flash, request, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FloatField, SelectField, TextAreaField, DateField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import datetime as dt_module
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
  'DATABASE_URL', 'sqlite:///finance.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
Bootstrap(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    transactions = db.relationship('Transaction', backref='user', lazy=True)
    goals = db.relationship('Goal', backref='user', lazy=True)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(20), nullable=False)  # 'income' or 'expense'
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))
    date = db.Column(db.DateTime, default=datetime.utcnow)

class Goal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    target_amount = db.Column(db.Float, nullable=False)
    current_amount = db.Column(db.Float, default=0.0)
    target_date = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Forms
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = SelectField('Remember me', choices=[('yes', 'Yes'), ('no', 'No')])

class SignupForm(FlaskForm):
    name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])

class TransactionForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired()])
    type = SelectField('Type', choices=[('income', 'Income'), ('expense', 'Expense')], validators=[DataRequired()])
    category = SelectField('Category', choices=[
        ('salary', 'Salary'), ('freelance', 'Freelance'), ('investment', 'Investment'),
        ('other_income', 'Other Income'), ('housing', 'Housing'), ('transportation', 'Transportation'),
        ('food', 'Food'), ('utilities', 'Utilities'), ('healthcare', 'Healthcare'),
        ('entertainment', 'Entertainment'), ('shopping', 'Shopping'), ('education', 'Education'),
        ('other_expense', 'Other Expense')
    ], validators=[DataRequired()])
    description = TextAreaField('Description')
    date = DateField('Date', default=datetime.utcnow, validators=[DataRequired()])

class GoalForm(FlaskForm):
    name = StringField('Goal Name', validators=[DataRequired(), Length(min=2, max=100)])
    target_amount = FloatField('Target Amount', validators=[DataRequired()])
    current_amount = FloatField('Current Amount', default=0.0)
    target_date = DateField('Target Date', validators=[DataRequired()])

# Flask-Login loader
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Get month and year from query parameters or use current month/year
    selected_month = request.args.get('month', datetime.now().month, type=int)
    selected_year = request.args.get('year', datetime.now().year, type=int)

    # Get available months/years with data for dropdown
    available_months = db.session.query(
        db.extract('month', Transaction.date).label('month'),
        db.extract('year', Transaction.date).label('year')
    ).filter(
        Transaction.user_id == current_user.id
    ).distinct().order_by(
        db.extract('year', Transaction.date).desc(),
        db.extract('month', Transaction.date).desc()
    ).all()

    # Get transactions for selected month/year
    transactions = Transaction.query.filter(
        Transaction.user_id == current_user.id,
        db.extract('month', Transaction.date) == selected_month,
        db.extract('year', Transaction.date) == selected_year
    ).order_by(Transaction.date.desc()).limit(5).all()

    goals = Goal.query.filter_by(user_id=current_user.id).all()

    # Calculate income, expenses, balance for selected month
    income = db.session.query(db.func.sum(Transaction.amount)).filter(
        Transaction.user_id == current_user.id,
        Transaction.type == 'income',
        db.extract('month', Transaction.date) == selected_month,
        db.extract('year', Transaction.date) == selected_year
    ).scalar() or 0

    expenses = db.session.query(db.func.sum(Transaction.amount)).filter(
        Transaction.user_id == current_user.id,
        Transaction.type == 'expense',
        db.extract('month', Transaction.date) == selected_month,
        db.extract('year', Transaction.date) == selected_year
    ).scalar() or 0

    balance = income - expenses

    # Calculate expense categories for selected month
    expense_categories = {}
    expense_transactions = Transaction.query.filter(
        Transaction.user_id == current_user.id,
        Transaction.type == 'expense',
        db.extract('month', Transaction.date) == selected_month,
        db.extract('year', Transaction.date) == selected_year
    ).all()

    for t in expense_transactions:
        if t.category in expense_categories:
            expense_categories[t.category] += t.amount
        else:
            expense_categories[t.category] = t.amount

    chart_data = {
        'income': income,
        'expenses': expenses,
        'balance': balance,
        'expense_categories': expense_categories,
        'current_month': datetime(selected_year, selected_month, 1).strftime('%B %Y'),
        'selected_month': selected_month,
        'selected_year': selected_year
    }

    return render_template('dashboard.html', 
                         transactions=transactions, 
                         goals=goals, 
                         chart_data=chart_data,
                         available_months=available_months,
                         current_month=selected_month,
                         current_year=selected_year,
                         datetime=datetime)

@app.route('/transactions')
@login_required
def transactions():
    transaction_type = request.args.get('type', 'all')
    search_query = request.args.get('search', '').strip().lower()
    month_filter = request.args.get('month', datetime.now().month, type=int)
    year_filter = request.args.get('year', datetime.now().year, type=int)

    query = Transaction.query.filter(
        Transaction.user_id == current_user.id,
        db.extract('month', Transaction.date) == month_filter,
        db.extract('year', Transaction.date) == year_filter
    )

    if transaction_type in ['income', 'expense']:
        query = query.filter_by(type=transaction_type)

    if search_query:
        query = query.filter(
            db.or_(
                Transaction.description.ilike(f'%{search_query}%'),
                Transaction.category.ilike(f'%{search_query}%')
            )
        )

    transactions = query.order_by(Transaction.date.desc()).all()

    available_months = db.session.query(
        db.extract('month', Transaction.date).label('month'),
        db.extract('year', Transaction.date).label('year')
    ).filter(
        Transaction.user_id == current_user.id
    ).distinct().order_by(
        db.extract('year', Transaction.date).desc(),
        db.extract('month', Transaction.date).desc()
    ).all()

    return render_template('transactions.html', 
                         transactions=transactions,
                         selected_type=transaction_type,
                         search_query=search_query,
                         selected_month=month_filter,
                         selected_year=year_filter,
                         available_months=available_months,
                         datetime=datetime)

@app.route('/login', methods=['GET', 'POST'])
def login():
  if current_user.is_authenticated:
    flash('You are already logged in!', 'info')
    return redirect(url_for('home'))
  form = LoginForm()
  if form.validate_on_submit():
    user = User.query.filter_by(email=form.email.data).first()
    if user and check_password_hash(user.password, form.password.data):
      login_user(user, remember=(form.remember.data == 'yes'))
      return redirect(url_for('dashboard'))
    else:
      flash('Invalid email or password', 'danger')
  return render_template('login.html', form=form)

def safe_password_hash(password):
  """Handle password hashing with version compatibility"""
  try:
    return generate_password_hash(password, method='scrypt')
  except ValueError:
    try:

      return generate_password_hash(password,
                                    method='pbkdf2:sha256',
                                    salt_length=16)
    except ValueError:
      return generate_password_hash(password,
                                    method='pbkdf2:sha256',
                                    salt_length=8)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
  if current_user.is_authenticated: 
    flash('Please logout before creating a new account!', 'info')
    return redirect(url_for('home'))
  form = SignupForm()
  if form.validate_on_submit():
    if form.password.data != form.confirm_password.data:
      flash('Passwords do not match', 'danger')
      return render_template('signup.html', form=form)

    existing_user = User.query.filter_by(email=form.email.data).first()
    if existing_user:
      flash('Email already registered', 'danger')
      return render_template('signup.html', form=form)

    try:
      hashed_password = safe_password_hash(form.password.data)
    except ValueError as e:
      flash('Error creating account. Please try again.', 'danger')
      app.logger.error(f'Password hashing error: {str(e)}')
      return render_template('signup.html', form=form)

    new_user = User(name=form.name.data,
                    email=form.email.data,
                    password=hashed_password)

    try:
      db.session.add(new_user)
      db.session.commit()
      flash('Account created successfully! Please log in.', 'success')
      return redirect(url_for('login'))
    except Exception as e:
      db.session.rollback()
      flash('Error creating account. Please try again.', 'danger')
      app.logger.error(f'Database error: {str(e)}')
      return render_template('signup.html', form=form)

  return render_template('signup.html', form=form)


@app.route('/logout')
@login_required
def logout():
  logout_user()
  flash('You have been logged out.', 'success')
  return redirect(url_for('home'))


@app.route('/add_transaction', methods=['GET', 'POST'])
@login_required
def add_transaction():
  form = TransactionForm()
  if form.validate_on_submit():
    new_transaction = Transaction(user_id=current_user.id,
                                  amount=form.amount.data,
                                  type=form.type.data,
                                  category=form.category.data,
                                  description=form.description.data,
                                  date=form.date.data)
    db.session.add(new_transaction)
    db.session.commit()
    flash('Transaction added successfully!', 'success')
    return redirect(url_for('dashboard'))
  return render_template('add_transaction.html', form=form)


@app.route('/add_goal', methods=['GET', 'POST'])
@login_required
def add_goal():
  form = GoalForm()
  if form.validate_on_submit():
    new_goal = Goal(user_id=current_user.id,
                    name=form.name.data,
                    target_amount=form.target_amount.data,
                    current_amount=form.current_amount.data,
                    target_date=form.target_date.data)
    db.session.add(new_goal)
    db.session.commit()
    flash('Savings goal added successfully!', 'success')
    return redirect(url_for('dashboard'))
  return render_template('add_goal.html', form=form)

@app.route('/transaction/<int:transaction_id>/edit', methods=['POST'])
@login_required
def edit_transaction(transaction_id):
  transaction = Transaction.query.get_or_404(transaction_id)
  if transaction.user_id != current_user.id:
    return jsonify({'success': False, 'message': 'Unauthorized'}), 403

  try:
    data = request.form
    transaction.description = data.get('description', transaction.description)
    transaction.category = data.get('category', transaction.category)

    # Validate amount
    try:
      amount = float(data.get('amount', transaction.amount))
      if amount <= 0:
        raise ValueError("Amount must be positive")
      transaction.amount = amount
    except (TypeError, ValueError) as e:
      return jsonify({
          'success': False,
          'message': 'Invalid amount: ' + str(e)
      }), 400

    # Validate date
    try:
      date_str = data.get('date')
      if date_str:
        transaction.date = datetime.strptime(date_str, '%Y-%m-%d')
    except ValueError as e:
      return jsonify({
          'success': False,
          'message': 'Invalid date format. Use YYYY-MM-DD'
      }), 400

    transaction.type = data.get('type', transaction.type)

    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Transaction updated successfully',
        'transaction': {
            'description': transaction.description,
            'category': transaction.category,
            'amount': transaction.amount,
            'type': transaction.type,
            'date': transaction.date.strftime('%Y-%m-%d'),
            'display_date': transaction.date.strftime('%b %d, %Y')
        }
    })
  except Exception as e:
    db.session.rollback()
    return jsonify({
        'success': False,
        'message': 'Server error: ' + str(e)
    }), 500


@app.route('/transaction/<int:transaction_id>/delete', methods=['POST'])
@login_required
def delete_transaction(transaction_id):
  transaction = Transaction.query.get_or_404(transaction_id)
  if transaction.user_id != current_user.id:
    abort(403)

  try:
    db.session.delete(transaction)
    db.session.commit()
    return jsonify({
        'success': True,
        'message': 'Transaction deleted successfully'
    })
  except Exception as e:
    db.session.rollback()
    return jsonify({'success': False, 'message': str(e)}), 400


@app.route('/goals')
@login_required
def goals():
  goals = Goal.query.filter_by(user_id=current_user.id).all()
  return render_template('goals.html', goals=goals)


@app.route('/goal/<int:goal_id>/add_funds', methods=['POST'])
@login_required
def add_funds(goal_id):
  goal = Goal.query.get_or_404(goal_id)
  if goal.user_id != current_user.id:
    abort(403)  # Forbidden

  try:
    amount = float(request.form.get('amount'))
    if amount <= 0:
      flash('Amount must be positive', 'danger')
      return redirect(url_for('goals'))

    goal.current_amount += amount
    db.session.commit()
    flash(f'Successfully added ₹{amount} to {goal.name}', 'success')
  except ValueError:
    flash('Invalid amount', 'danger')
  except Exception as e:
    db.session.rollback()
    flash('Error adding funds', 'danger')
    app.logger.error(f"Error adding funds: {str(e)}")

  return redirect(url_for('goals'))


@app.route('/goal/<int:goal_id>/delete', methods=['POST'])
@login_required
def delete_goal(goal_id):
  goal = Goal.query.get_or_404(goal_id)
  if goal.user_id != current_user.id:
    abort(403)  # Forbidden

  try:
    db.session.delete(goal)
    db.session.commit()
    flash(f'Goal "{goal.name}" deleted successfully', 'success')
  except Exception as e:
    db.session.rollback()
    flash('Error deleting goal', 'danger')
    app.logger.error(f"Error deleting goal: {str(e)}")

  return redirect(url_for('goals'))


# Initialize database
with app.app_context():
  db.create_all()
  
if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8080,debug=True) 
