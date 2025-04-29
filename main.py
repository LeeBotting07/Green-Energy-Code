from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import re
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.google import make_google_blueprint, google
import os

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = '007'


# Google OAuth configuration
app.config["GOOGLE_OAUTH_CLIENT_ID"] = "805956887533-5p9rlgosfg2afflgt54hevag5q5gmo0v.apps.googleusercontent.com"
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = "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"

google_bp = make_google_blueprint(
    client_id=app.config["GOOGLE_OAUTH_CLIENT_ID"],
    client_secret=app.config["GOOGLE_OAUTH_CLIENT_SECRET"],
    redirect_to="account",
    scope=[
        "https://www.googleapis.com/auth/userinfo.profile",
        "openid",
        "https://www.googleapis.com/auth/userinfo.email"
    ]
)
google_bp.authorization_url_params = {"prompt": "select_account"}
app.register_blueprint(google_bp, url_prefix="/login")

@app.route('/')
@app.route('/home')
def home():
    return render_template('index.html', title='Rolsa | Home')

@app.route('/about')
def about():
    if 'email' not in session:
        flash("You need to log in to access this page.", 'error')
        return redirect(url_for('login'))
    return render_template('about.html', title='Rolsa | About')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if 'email' not in session:
        flash("You need to log in to contact us.", 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form.get('name')
        email = session['email']
        subject = request.form.get('subject')
        message = request.form.get('message')

        if not name or not subject or not message:
            flash('All fields are required.', 'error')
            return render_template('contact.html', title="Rolsa | Contact")

        try:
            with sqlite3.connect("rolsa.db") as con:
                cur = con.cursor()
                cur.execute('''
                    INSERT INTO contact_messages (name, email, subject, message)
                    VALUES (?, ?, ?, ?)
                ''', (name, email, subject, message))
                con.commit()
        except sqlite3.Error as e:
            flash(f'Database error: {e}', 'error')
            return render_template('contact.html', title="Rolsa | Contact")

        flash('Thank you for contacting Rolsa! We will get back to you soon.', 'success')
        return render_template('contact.html', title="Rolsa | Contact")

    return render_template('contact.html', title="Rolsa | Contact")

@app.route('/energy')
def energy():
    if 'email' not in session:
        flash("You need to log in to access this page.", 'error')
        return redirect(url_for('login'))
    return render_template('energy.html', title='Rolsa | Energy')

def calculate_energy_cost(start_reading, end_reading, start_date, end_date, kwh_cost, standing_charge):
    if start_reading >= end_reading:
        flash("End reading must be greater than start reading.", "error")
        return None
    
    days_used = (end_date - start_date).days + 1
    if days_used <= 0:
        flash("End date must be after start date.", "error")
        return None
    
    kwh_used = end_reading - start_reading
    total_cost = (kwh_used * kwh_cost) + (days_used * standing_charge)
    
    return {"kwh_used": kwh_used, "total_cost": total_cost}

@app.route("/calculate_energy", methods=["GET", "POST"])
def calculate_energy():
    result = None
    if request.method == "POST":
        try:
            start_reading = float(request.form["readingStart"])
            end_reading = float(request.form["readingEnd"])
            start_date = datetime.strptime(request.form["dateStart"], "%Y-%m-%d")
            end_date = datetime.strptime(request.form["dateEnd"], "%Y-%m-%d")
            kwh_cost = float(request.form["kwhCost"])
            standing_charge = float(request.form["standingCharge"])

            # Enhanced validation
            if start_reading < 0 or end_reading < 0:
                flash("Readings must be non-negative.", "error")
                return redirect(url_for("calculate_energy"))

            if end_reading <= start_reading:
                flash("End reading must be greater than starting reading.", "error")
                return redirect(url_for("calculate_energy"))

            if end_date <= start_date:
                flash("End date must be after start date.", "error")
                return redirect(url_for("calculate_energy"))

            result = calculate_energy_cost(start_reading, end_reading, start_date, end_date, kwh_cost, standing_charge)
            
            if result:
                with sqlite3.connect("rolsa.db") as con:
                    cur = con.cursor()
                    cur.execute("INSERT INTO energy_readings (start_reading, end_reading, start_date, end_date, kwh_cost, standing_charge, kwh_used, total_cost) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                (start_reading, end_reading, start_date, end_date, kwh_cost, standing_charge, result["kwh_used"], result["total_cost"]))
                    con.commit()
                flash("Calculation saved successfully!", "success")
                return redirect(url_for("calculate_energy"))
        except ValueError:
            flash("Invalid input. Please enter valid numbers.", "error")
        except sqlite3.Error as e:
            flash(f"Database error: {e}. Please try again later.", "error")
        except Exception as e:
            flash(f"An unexpected error occurred: {str(e)}", "error")
    
    return render_template("calculate_energy.html", result=result)


@app.route('/carbon_footprint')
def carbon_footprint():
    if 'email' not in session:
        flash("You need to log in to access this page.", 'error')
        return redirect(url_for('login'))
    return render_template('carbon_footprint.html', title='Rolsa | Carbon Footprint')

def validate_date(date_str):
    try:
        # Expecting date in DD-MM-YYYY format
        if not date_str:
            return False
        day, month, year = map(int, date_str.split('-'))
        
        # Check if the year is valid (must be exactly 4 digits)
        if len(str(year)) != 4 or year < 1000 or year > 9999:
            return False
        
        return 1 <= day <= 31 and 1 <= month <= 12
    except (ValueError, AttributeError):
        return False

@app.route('/meeting_booking', methods=['GET', 'POST'])  
def meeting_booking():
    if 'email' not in session:
        flash("You need to log in to access this page.", 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        # Get form data safely with default None values
        name = request.form.get('name')
        email = request.form.get('email')
        date = request.form.get('date')  # This will be in DD-MM-YYYY format
        time = request.form.get('time')
        reason = request.form.get('reason')

        # Check if all fields are filled
        if not all([name, email, date, time, reason]):
            flash('All fields are required', 'error')
            return redirect(url_for('meeting_booking'))

        # Validate the date format
        if not validate_date(date):
            flash('Invalid date format. Please use DD-MM-YYYY.', 'error')
            return redirect(url_for('meeting_booking'))

        try:
            # Continue with existing booking logic
            with sqlite3.connect("rolsa.db") as con:
                cur = con.cursor()
                cur.execute("INSERT INTO meetings (name, email, date, time, reason) VALUES (?, ?, ?, ?, ?)", 
                          (name, email, date, time, reason))
                con.commit()
                flash('Meeting booked successfully!', 'success')
                return redirect(url_for('account'))

        except Exception as e:
            flash(f'Error booking meeting: {str(e)}', 'error')
            return redirect(url_for('meeting_booking'))

    # Return the rendered template for GET requests
    return render_template('meeting_booking.html', title="Rolsa | Meeting Booking")


@app.route('/consultation_booking', methods=['GET', 'POST'])
def consultation_booking():
    if 'email' not in session:
        flash("You need to log in to access this page.", 'error')
        return redirect(url_for('login'))

    if request.method == 'GET':
        return render_template('consultation_booking.html', title="Rolsa | Consultation Booking")

    if request.method == 'POST':
        # Get form data
        date = request.form.get('date')  # This will be in DD-MM-YYYY format
        time = request.form.get('time')
        name = request.form.get('name')
        email = request.form.get('email')
        reason = request.form.get('reason')

        # Validate all fields exist
        if not all([date, time, name, email, reason]):
            flash('All fields are required', 'error')
            return redirect(url_for('consultation_booking'))

        # Validate the date format
        if not validate_date(date):
            flash('Invalid date format. Please use DD-MM-YYYY.', 'error')
            return redirect(url_for('consultation_booking'))

        try:
            with sqlite3.connect("rolsa.db") as con:
                cur = con.cursor()
                cur.execute("INSERT INTO consultation_bookings (name, email, date, time, reason) VALUES (?, ?, ?, ?, ?)",
                            (name, email, date, time, reason))
                con.commit()
                flash('Consultation booked successfully!', 'success')
                return redirect(url_for('account'))
        except sqlite3.Error as e:
            flash(f"Database error: {e}", 'error')
            return redirect(url_for('consultation_booking'))

@app.route('/submit_meeting_booking', methods=['POST'])
def submit_meeting_booking():
    name = request.form.get('name')
    email = request.form.get('email')
    date = request.form.get('date')
    time = request.form.get('time')
    reason = request.form.get('reason')  
    
    # Save booking to the database
    with sqlite3.connect("rolsa.db") as con:
        cur = con.cursor()
        cur.execute("INSERT INTO meetings (name, email, date, time, reason) VALUES (?, ?, ?, ?, ?)", (name, email, date, time, reason))
        con.commit()

    session['booking_details'] = {'name': name, 'email': email, 'date': date, 'time': time, 'reason': reason}
    flash("Meeting booked successfully!", 'success')
    return redirect(url_for('booking_confirmation', name=name, email=email, date=date, time=time, reason=reason))  # Pass reason to confirmation

@app.route('/submit_consultation_booking', methods=['POST'])
def submit_consultation_booking():
    name = request.form.get('name')
    email = request.form.get('email')
    date = request.form.get('date')
    time = request.form.get('time')
    reason = request.form.get('reason')  
    
    # Save booking to the database
    with sqlite3.connect("rolsa.db") as con:
        cur = con.cursor()
        cur.execute("INSERT INTO consultation_bookings (name, email, date, time, reason) VALUES (?, ?, ?, ?, ?)", (name, email, date, time, reason))
        con.commit()

    session['booking_details'] = {'name': name, 'email': email, 'date': date, 'time': time, 'reason': reason}
    flash("Consultation booked successfully!", 'success')
    return redirect(url_for('booking_confirmation', name=name, email=email, date=date, time=time, reason=reason))  # Pass reason to confirmation

@app.route('/booking_confirmation')
def booking_confirmation():
    booking_details = session.get('booking_details', {})
    name = booking_details.get('name')
    email = booking_details.get('email')
    date = booking_details.get('date')
    time = booking_details.get('time')
    reason = booking_details.get('reason')
    return render_template('booking_confirmation.html', name=name, email=email, date=date, time=time, reason=reason)  # Pass reason to confirmation

@app.route('/booking')
def booking():
    if 'email' not in session:
        flash("You need to log in to access the booking page.", 'error')
        return redirect(url_for('login'))
    return render_template('booking.html', title='Rolsa | Booking')

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip() 
        first_name = request.form.get('first_name', '').strip() 
        last_name = request.form.get('last_name', '').strip()   
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        print(f"Username: {username}, First Name: {first_name}, Last Name: {last_name}, Email: {email}, Password: {password}, Confirm Password: {confirm_password}")

        # Validation checks
        if not username or not first_name or not last_name or not email or not password or not confirm_password:
            flash("All fields are required.", 'error')
            return redirect(url_for('register'))

        if not validate_email(email):
            flash("Invalid email format.", 'error')
            return redirect(url_for('register'))

        if len(password) < 8:
            flash("Password must be at least 8 characters long.", 'error')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash("Passwords do not match.", 'error')
            return redirect(url_for('register'))

        try:
            with sqlite3.connect("rolsa.db") as con:
                cur = con.cursor()
                # Check if email already exists
                cur.execute("SELECT email FROM users WHERE email = ?", (email,))
                if cur.fetchone():
                    flash("An account with this email already exists.", 'error')
                    return redirect(url_for('register'))

                # Hash the password and store the user
                hashed_password = generate_password_hash(password)
                cur.execute("INSERT INTO users (username, first_name, last_name, email, password) VALUES (?, ?, ?, ?, ?)", (username, first_name, last_name, email, hashed_password))
                con.commit()
                flash("Registration successful. You can now log in.", 'success')
                return redirect(url_for('login'))

        except sqlite3.Error as e:
            flash(f"Database error: {e}. Please try again later.", 'error')
            return redirect(url_for('register'))

    return render_template('register.html', title="Rolsa | Register")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')

        # Validation checks
        if not email or not password:
            flash("Both email and password are required.", 'error')
            return redirect(url_for('login'))

        if not validate_email(email):
            flash("Invalid email format.", 'error')
            return redirect(url_for('login'))

        try:
            with sqlite3.connect("rolsa.db") as con:
                cur = con.cursor()
                # Check if email exists
                cur.execute("SELECT email, password FROM users WHERE email = ?", (email,))
                data = cur.fetchone()
                if not data:
                    flash("No account found with this email. Please register first.", 'error')
                    return redirect(url_for('login'))

                stored_email, stored_password = data
                # Check if password is empty (OAuth-only account)
                if stored_password == '':
                    flash("This account uses Google Sign-In only. Please use the 'Sign in with Google' button.", 'error')
                    return redirect(url_for('login'))

                # Verify password
                if not check_password_hash(stored_password, password):
                    flash("Incorrect password. Please try again.", 'error')
                    return redirect(url_for('login'))

                # Successful login
                session['email'] = stored_email
                flash("Logged in successfully.", 'success')
                return redirect(url_for('account'))

        except sqlite3.Error as e:
            flash(f"Database error: {e}. Please try again later.", 'error')
            return redirect(url_for('login'))

    return render_template('login.html', title="Rolsa | Login")

@app.route('/account')
def account():
    # Check if user is logged in via OAuth or session
    if not google.authorized and 'email' not in session:
        return redirect(url_for('login'))

    if google.authorized:
        resp = google.get("/oauth2/v2/userinfo")
        if resp.ok:
            user_info = resp.json()
            email = user_info["email"]
            session['email'] = email

            # Extract first and last name from user_info if available
            first_name = user_info.get("given_name", "GoogleUser")
            last_name = user_info.get("family_name", "OAuth")

            # Check if user exists in DB, if not create new user
            try:
                with sqlite3.connect("rolsa.db") as con:
                    cur = con.cursor()
                    cur.execute("SELECT email FROM users WHERE email = ?", (email,))
                    existing_user = cur.fetchone()
                    if not existing_user:
                        username = email.split('@')[0]
                        cur.execute("INSERT INTO users (username, first_name, last_name, email, password) VALUES (?, ?, ?, ?, ?)",
                                    (username, first_name, last_name, email, ''))
                        con.commit()
                        # Redirect new OAuth user to set password page
                        return redirect(url_for('set_password'))
            except sqlite3.Error as e:
                flash(f"Database error: {e}", "error")
                return redirect(url_for('login'))

        else:
            flash("Failed to fetch user info from Google.", "error")
            return redirect(url_for('login'))
    else:
        email = session.get('email')

    try:
        with sqlite3.connect("rolsa.db") as con:
            cur = con.cursor()

            # Get user data
            cur.execute("SELECT first_name, last_name FROM users WHERE email = ?", (email,))
            user_data = cur.fetchone()

            if user_data:
                first_name, last_name = user_data

                # Fetch meetings - simplified query without date formatting
                cur.execute("SELECT date, time, reason FROM meetings WHERE email = ?", (email,))
                meetings_data = cur.fetchall()
                meetings = [
                    {
                        'date': meeting[0],
                        'time': meeting[1],
                        'reason': meeting[2]
                    }
                    for meeting in meetings_data
                ]

                # Fetch consultations - simplified query without date formatting 
                cur.execute("SELECT date, time, reason FROM consultation_bookings WHERE email = ?", (email,))
                consultation_data = cur.fetchall()
                consultations = [
                    {
                        'date': consult[0],
                        'time': consult[1],
                        'reason': consult[2]
                    }
                    for consult in consultation_data
                ]

                # Debug print
                print(f"Found {len(meetings)} meetings and {len(consultations)} consultations")

                return render_template(
                    'account.html',
                    title="Rolsa | Account",
                    first_name=first_name,
                    last_name=last_name,
                    email=email,
                    meetings=meetings,
                    consultations=consultations
                )
            else:
                flash("User data not found.", 'error')
                return redirect(url_for('login'))

    except sqlite3.Error as e:
        print(f"Database error: {e}")  # Debug print
        flash(f"Database error: {e}", 'error')
        return redirect(url_for('login'))

@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    if 'email' not in session:
        flash("You need to log in to change your password.", 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Validation checks
        if not current_password or not new_password or not confirm_password:
            flash("All fields are required.", 'error')
            return redirect(url_for('change_password'))

        if len(new_password) < 8:
            flash("Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.", 'error')
            return redirect(url_for('change_password'))

        if not re.search(r'[A-Z]', new_password):
            flash("Password must include at least one uppercase letter.", 'error')
            return redirect(url_for('change_password'))

        if not re.search(r'[a-z]', new_password):
            flash("Password must include at least one lowercase letter.", 'error')
            return redirect(url_for('change_password'))

        if not re.search(r'[0-9]', new_password):
            flash("Password must include at least one number.", 'error')
            return redirect(url_for('change_password'))

        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', new_password):
            flash("Password must include at least one special character.", 'error')
            return redirect(url_for('change_password'))

        if new_password != confirm_password:
            flash("Passwords do not match.", 'error')
            return redirect(url_for('change_password'))

        try:
            with sqlite3.connect("rolsa.db") as con:
                cur = con.cursor()
                cur.execute("SELECT password FROM users WHERE email = ?", (session['email'],))
                user_password = cur.fetchone()

                if user_password and check_password_hash(user_password[0], current_password):
                    hashed_password = generate_password_hash(new_password)
                    cur.execute("UPDATE users SET password = ? WHERE email = ?", (hashed_password, session['email']))
                    con.commit()
                    flash("Password changed successfully.", 'success')
                    return redirect(url_for('account'))
                else:
                    flash("Current password is incorrect.", 'error')
                    return redirect(url_for('change_password'))
        except sqlite3.Error as e:
            flash(f"Database error: {e}", 'error')
            return redirect(url_for('change_password'))

    return render_template('change_password.html', title="Rolsa | Change Password")

@app.route('/edit-profile', methods=['GET', 'POST'])
def edit_profile():
    if 'email' not in session:
        flash("You need to log in to edit your profile.", 'error')
        return redirect(url_for('login'))
    
    try:
        with sqlite3.connect("rolsa.db") as con:
            cur = con.cursor()
            
            if request.method == 'POST':
                # Get form data
                first_name = request.form.get('first_name', '').strip()
                last_name = request.form.get('last_name', '').strip()
                email = request.form.get('email', '').strip()
                
                # Validation
                if not all([first_name, last_name, email]):
                    flash("All fields are required.", 'error')
                    return redirect(url_for('edit_profile'))
                
                if not validate_email(email):
                    flash("Invalid email format.", 'error')
                    return redirect(url_for('edit_profile'))
                
                # Check if new email already exists (if email was changed)
                if email != session['email']:
                    cur.execute("SELECT email FROM users WHERE email = ? AND email != ?", (email, session['email']))
                    if cur.fetchone():
                        flash("An account with this email already exists.", 'error')
                        return redirect(url_for('edit_profile'))
                
                # Update user data
                cur.execute("""
                    UPDATE users 
                    SET first_name = ?, last_name = ?, email = ?
                    WHERE email = ?
                """, (first_name, last_name, email, session['email']))
                
                con.commit()
                
                # Update session email if it was changed
                session['email'] = email
                
                flash("Profile updated successfully!", 'success')
                return redirect(url_for('account'))
            
            else:
                cur.execute("SELECT first_name, last_name, email FROM users WHERE email = ?", (session['email'],))
                user_data = cur.fetchone()
                
                if user_data:
                    return render_template('edit_profile.html',
                                        title="Rolsa | Edit Profile",
                                        user_data=user_data)
                else:
                    flash("User data not found.", 'error')
                    return redirect(url_for('account'))
                    
    except sqlite3.Error as e:
        flash(f"Database error: {e}", 'error')
        return redirect(url_for('account'))

@app.route('/cancel_booking', methods=['GET', 'POST'])
def cancel_booking():
    if 'email' not in session:
        flash("You need to log in to cancel a booking.", 'error')
        return redirect(url_for('login'))

    if request.method == 'GET':
        # Fetch both meetings and consultations for the user
        try:
            with sqlite3.connect("rolsa.db") as con:
                cur = con.cursor()
                # Get meetings
                cur.execute("SELECT id, date, time, reason, 'meeting' as type FROM meetings WHERE email = ?", (session['email'],))
                meetings = cur.fetchall()
                
                # Get consultations
                cur.execute("SELECT id, date, time, reason, 'consultation' as type FROM consultation_bookings WHERE email = ?", (session['email'],))
                consultations = cur.fetchall()
                
                # Combine all bookings
                items = meetings + consultations
                return render_template('cancel_booking.html', title="Rolsa | Cancel Booking", items=items)
        except sqlite3.Error as e:
            flash(f"Database error: {e}", 'error')
            return redirect(url_for('account'))

    elif request.method == 'POST':
        booking_type = request.form.get('type')
        booking_id = request.form.get('booking_id')

        if not booking_id:
            flash("Please select a booking to cancel.", 'error')
            return redirect(url_for('cancel_booking'))

        try:
            with sqlite3.connect("rolsa.db") as con:
                cur = con.cursor()
                if booking_type == 'meeting':
                    cur.execute("DELETE FROM meetings WHERE id = ? AND email = ?", (booking_id, session['email']))
                else:
                    cur.execute("DELETE FROM consultation_bookings WHERE id = ? AND email = ?", (booking_id, session['email']))
                if cur.rowcount > 0:
                    con.commit()
                    flash("Booking canceled successfully!", 'success')
                else:
                    flash("Booking not found or you don't have permission to cancel it.", 'error')
                return redirect(url_for('account'))
        except sqlite3.Error as e:
            flash(f"Database error: {e}", 'error')
            return redirect(url_for('account'))

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", 'success')
    return redirect(url_for('home'))

@app.errorhandler(404)
def error_404(error):   
    return render_template('404.html', title="404 Error", error_message=str(error)), 404

if __name__ == '__main__':
    app.run(debug=True)
