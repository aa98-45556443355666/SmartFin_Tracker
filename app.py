from flask import Flask, render_template, redirect, url_for, flash, request, abort, jsonify
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, FloatField, SelectField, TextAreaField, DateField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_wtf.csrf import CSRFProtect
import os
from dotenv import load_dotenv
from database import (engine,
    get_user_by_email, add_user, get_user_by_id,
    get_transactions, add_transaction, update_transaction, delete_transaction, get_transaction_by_id,
    get_goals, add_goal, update_goal, delete_goal, get_goal_by_id, add_funds_to_goal,
    get_income_expense_summary, get_expense_categories
)

load_dotenv()

app = Flask(__name__)
csrf = CSRFProtect(app)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
Bootstrap(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(UserMixin):
    def __init__(self, user_dict):
        self.id = user_dict['id']
        self.name = user_dict['name']
        self.email = user_dict['email']
        self.password = user_dict['password']
        self.created_at = user_dict.get('created_at')
        self._user_dict = user_dict

    def get_id(self):
        return str(self.id)


class TransactionForm(FlaskForm):
    amount = FloatField('Amount', validators=[DataRequired()])
    type = SelectField('Type', choices=[
                       ('income', 'Income'), ('expense', 'Expense')], validators=[DataRequired()])
    category = SelectField('Category', choices=[
        ('salary', 'Salary'), ('freelance',
                               'Freelance'), ('investment', 'Investment'),
        ('other_income', 'Other Income'), ('housing',
                                           'Housing'), ('transportation', 'Transportation'),
        ('food', 'Food'), ('utilities', 'Utilities'), ('healthcare', 'Healthcare'),
        ('entertainment', 'Entertainment'), ('shopping',
                                             'Shopping'), ('education', 'Education'),
        ('other_expense', 'Other Expense')
    ], validators=[DataRequired()])
    description = TextAreaField('Description')
    date = DateField('Date', default=datetime.utcnow,
                     validators=[DataRequired()])



class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = SelectField('Remember Me', choices=[
                           ('yes', 'Yes'), ('no', 'No')], default='no')



class SignupForm(FlaskForm):
    name = StringField('Name', validators=[
                       DataRequired(), Length(min=2, max=100)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[
                             DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[
                                     DataRequired(), Length(min=6)])


class GoalForm(FlaskForm):
    name = StringField('Goal Name', validators=[
                       DataRequired(), Length(min=2, max=100)])
    target_amount = FloatField('Target Amount', validators=[DataRequired()])
    current_amount = FloatField('Current Amount', default=0.0)
    target_date = DateField('Target Date', validators=[DataRequired()])


@login_manager.user_loader
def load_user(user_id):
    user = get_user_by_id(int(user_id))
    return User(user) if user else None


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/dashboard')
@login_required
def dashboard():
    selected_month = request.args.get('month', datetime.now().month, type=int)
    selected_year = request.args.get('year', datetime.now().year, type=int)
    user_id = current_user.id

    with engine.connect() as conn:
        transactions = get_transactions(conn,
            user_id, month=selected_month, year=selected_year, limit=5)
        goals = get_goals(conn,user_id)
        income,expenses = get_income_expense_summary(conn,
            user_id, selected_month, selected_year)
       
        expense_categories = get_expense_categories(conn,
            user_id, selected_month, selected_year)
        
    balance = income - expenses
    
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
                           datetime=datetime)


@app.route('/transactions')
@login_required
def transactions():
    transaction_type = request.args.get('type', 'all')
    search_query = request.args.get('search', '').strip().lower()
    month_filter = request.args.get('month', datetime.now().month, type=int)
    year_filter = request.args.get('year', datetime.now().year, type=int)
    user_id = current_user.id

    with engine.connect() as conn:
        transactions = get_transactions(conn,user_id, month=month_filter, year=year_filter,
                                        type_filter=transaction_type if transaction_type != 'all' else None, search=search_query)
        
    return render_template('transactions.html',
                           transactions=transactions,
                           selected_type=transaction_type,
                           search_query=search_query,
                           selected_month=month_filter,
                           selected_year=year_filter,
                           datetime=datetime)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash('You are already logged in!', 'info')
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = get_user_by_email(form.email.data)
        if user and check_password_hash(user['password'], form.password.data):
            login_user(User(user), remember=(form.remember.data == 'yes'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    return render_template('login.html', form=form)


def safe_password_hash(password):
    try:
        return generate_password_hash(password, method='scrypt')
    except ValueError:
        try:
            return generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
        except ValueError:
            return generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)


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
        existing_user = get_user_by_email(form.email.data)
        if existing_user:
            flash('Email already registered', 'danger')
            return render_template('signup.html', form=form)
        try:
            hashed_password = safe_password_hash(form.password.data)
        except ValueError as e:
            flash('Error creating account. Please try again.', 'danger')
            app.logger.error(f'Password hashing error: {str(e)}')
            return render_template('signup.html', form=form)
        if add_user(form.name.data, form.email.data, hashed_password):
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Error creating account. Please try again.', 'danger')
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
def add_transaction_route():
    form = TransactionForm()
    if form.validate_on_submit():
        if add_transaction(current_user.id, form.amount.data, form.type.data, form.category.data, form.description.data, form.date.data):
            flash('Transaction added successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Error adding transaction.', 'danger')
    return render_template('add_transaction.html', form=form)


@app.route('/add_goal', methods=['GET', 'POST'])
@login_required
def add_goal_route():
    form = GoalForm()
    if form.validate_on_submit():
        if add_goal(current_user.id, form.name.data, form.target_amount.data, form.current_amount.data, form.target_date.data):
            flash('Savings goal added successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Error adding goal.', 'danger')
    return render_template('add_goal.html', form=form)


@app.route('/transaction/<int:transaction_id>/edit', methods=['POST'])
@login_required
def edit_transaction(transaction_id):
    transaction = get_transaction_by_id(transaction_id, current_user.id)
    if not transaction:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    try:
        data = request.form
        description = data.get('description', transaction['description'])
        category = data.get('category', transaction['category'])
        try:
            amount = float(data.get('amount', transaction['amount']))
            if amount <= 0:
                raise ValueError("Amount must be positive")
        except (TypeError, ValueError) as e:
            return jsonify({'success': False, 'message': 'Invalid amount: ' + str(e)}), 400
        try:
            date_str = data.get('date')
            if date_str:
                date = datetime.strptime(date_str, '%Y-%m-%d')
            else:
                date = transaction['date']
        except ValueError as e:
            return jsonify({'success': False, 'message': 'Invalid date format. Use YYYY-MM-DD'}), 400
        type_ = data.get('type', transaction['type'])
        if update_transaction(transaction_id, current_user.id, amount, type_, category, description, date):
            updated = get_transaction_by_id(transaction_id, current_user.id)
            return jsonify({
                'success': True,
                'message': 'Transaction updated successfully',
                'transaction': {
                    'description': updated['description'],
                    'category': updated['category'],
                    'amount': updated['amount'],
                    'type': updated['type'],
                    'date': updated['date'].strftime('%Y-%m-%d'),
                    'display_date': updated['date'].strftime('%b %d, %Y')
                }
            })
        else:
            return jsonify({'success': False, 'message': 'Error updating transaction'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': 'Server error: ' + str(e)}), 500


@app.route('/transaction/<int:transaction_id>/delete', methods=['POST'])
@login_required
def delete_transaction_route(transaction_id):
    if delete_transaction(transaction_id, current_user.id):
        return jsonify({'success': True, 'message': 'Transaction deleted successfully'})
    else:
        return jsonify({'success': False, 'message': 'Error deleting transaction'}), 400


@app.route('/goals')
@login_required
def goals():

    with engine.connect() as conn:
        goals = get_goals(conn,current_user.id)
    for goal in goals:
        try:
            progress = (goal['current_amount'] / goal['target_amount']
                        ) * 100 if goal['target_amount'] else 0
        except Exception:
            progress = 0
        goal['progress'] = round(progress, 1)
    return render_template('goals.html', goals=goals)


@app.route('/goal/<int:goal_id>/edit', methods=['POST'])
@login_required
def edit_goal(goal_id):
    goal = get_goal_by_id(goal_id, current_user.id)
    if not goal:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    try:
        data = request.get_json()
        if not data.get('name') or len(data['name']) < 2:
            return jsonify({'success': False, 'message': 'Name must be at least 2 characters'}), 400
        try:
            target_amount = float(data['target_amount'])
            current_amount = float(data['current_amount'])
            if target_amount <= 0 or current_amount < 0:
                raise ValueError("Amounts must be positive")
        except (ValueError, TypeError):
            return jsonify({'success': False, 'message': 'Invalid amount values'}), 400
        try:
            target_date = datetime.strptime(
                data['target_date'], '%Y-%m-%d').date()
            if target_date < datetime.now().date():
                return jsonify({'success': False, 'message': 'Target date cannot be in the past'}), 400
        except ValueError:
            return jsonify({'success': False, 'message': 'Invalid date format'}), 400
        if update_goal(goal_id, current_user.id, data['name'], target_amount, current_amount, target_date):
            updated = get_goal_by_id(goal_id, current_user.id)
            return jsonify({
                'success': True,
                'message': 'Goal updated successfully',
                'goal': {
                    'name': updated['name'],
                    'target_amount': updated['target_amount'],
                    'current_amount': updated['current_amount'],
                    'target_date': updated['target_date'].strftime('%Y-%m-%d')
                }
            })
        else:
            return jsonify({'success': False, 'message': 'Error updating goal'}), 500
    except Exception as e:
        return jsonify({'success': False, 'message': f'Error updating goal: {str(e)}'}), 500


@app.route('/goal/<int:goal_id>/add_funds', methods=['POST'])
@login_required
def add_funds(goal_id):
    try:
        amount = float(request.form.get('amount'))
        if amount <= 0:
            flash('Amount must be positive', 'danger')
            return redirect(url_for('goals'))
        if add_funds_to_goal(goal_id, current_user.id, amount):
            flash(f'Successfully added ₹{amount} to goal', 'success')
        else:
            flash('Error adding funds', 'danger')
    except ValueError:
        flash('Invalid amount', 'danger')
    except Exception as e:
        flash('Error adding funds', 'danger')
        app.logger.error(f"Error adding funds: {str(e)}")
    return redirect(url_for('goals'))


@app.route('/goal/<int:goal_id>/delete', methods=['POST'])
@login_required
def delete_goal_route(goal_id):
    if delete_goal(goal_id, current_user.id):
        flash('Goal deleted successfully', 'success')
    else:
        flash('Error deleting goal', 'danger')
    return redirect(url_for('goals'))


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
