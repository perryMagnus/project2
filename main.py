from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, current_user, login_required
from flask_wtf import FlaskForm, CSRFProtect
from wtforms.fields import SelectField, SubmitField, TextAreaField, StringField, DateField, SelectMultipleField, BooleanField, PasswordField, FileField
from wtforms.validators import DataRequired, Email, Length, ValidationError
from flask_bcrypt import Bcrypt
import base64
import datetime

admin_login = "perryMagnus_1" 
admin_password = "6TgDjw2sFpLX9nEaRvYqZbUi"


app = Flask(__name__)
csrf = CSRFProtect(app)
bcrypt = Bcrypt(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "mysql://perry:<password>@127.0.0.1:3306/patient_doctor_appointment"
db = SQLAlchemy(app)

app.config["SECRET_KEY"] = "grubasek1"

login_manager = LoginManager(app)
login_manager.init_app(app)

login_manager.login_view = "/"

doctor_specialties = [
    ('cardiologist', 'Cardiologist'),
    ('dermatologist', 'Dermatologist'),
    ('pediatrician', 'Pediatrician'),
    ('orthopedic_surgeon', 'Orthopedic Surgeon'),
    ('neurologist', 'Neurologist'),
    ('obstetrician_gynecologist', 'Obstetrician & Gynecologist'),
    ('oncologist', 'Oncologist'),
    ('ophthalmologist', 'Ophthalmologist'),
    ('radiologist', 'Radiologist'),
    ('surgeon', 'Surgeon'),]

def future_date(form, field):
    today = datetime.datetime.now().date()
    if field.data < today + datetime.timedelta(days=1):
        raise ValidationError('Select a date starting from tomorrow.')

class User(db.Model, UserMixin):
    __abstract__ = True

    id = db.Column(db.Integer, primary_key = True, autoincrement = True)

    username = db.Column(db.String(30), nullable = False, unique = True)
    password = db.Column(db.String(60), nullable = False)
    fname = db.Column(db.String(30), nullable = False)
    lname = db.Column(db.String(30), nullable = False)
    date_of_birth = db.Column(db.Date, nullable = False)
    email = db.Column(db.String(60), nullable = False, unique = True)
    phone_number = db.Column(db.String(11), nullable = False, unique = True)
    active = db.Column(db.Boolean, default = False)

    def is_authenticated(self):
        return True if self.id is not None else False
    
    def is_anonymous(self):
        return True if self.id is None else False
    
    def is_active(self):
        return self.active

    def get_id(self):
        return str(self.id)

class Doctor(User):
    __tablename__ = "doctors"

    specialization = db.Column(db.String(60), nullable = False)
    dyploma = db.Column(db.LargeBinary, nullable = False)
    personal_ID = db.Column(db.LargeBinary, nullable = False)
    verified = db.Column(db.Boolean, default = False)
    working_hours = db.Column(db.String(20), nullable = False)

    role = db.Column(db.String(30), default = "doctor")

    appointments = db.relationship("Appointment", back_populates = "doctor")

class Patient(User):
    __tablename__ = "patients"

    role = db.Column(db.String(30), default = "patient")

    appointments = db.relationship("Appointment", back_populates = "patient")

class Admin(User):
    __tablename__ = "admins"

    role = db.Column(db.String(30), default = "admin")

class Appointment(db.Model):
    __tablename__ = "appointments"

    id = db.Column(db.Integer, primary_key = True, autoincrement = True)
    doctor_id = db.Column(db.Integer, db.ForeignKey("doctors.id"))
    patient_id = db.Column(db.Integer, db.ForeignKey("patients.id"))
    date = db.Column(db.Date)
    hour = db.Column(db.String(100))
    avaiable = db.Column(db.Boolean, default = True)

    doctor =  db.relationship("Doctor", back_populates = "appointments")
    patient = db.relationship("Patient", back_populates = "appointments")


class Register(FlaskForm):
    username = StringField("Username",render_kw={"placeholder":"username"}, validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min = 8, 
                                                                            message = "Minimum length is 8 characters.")])
    first_name = StringField("First name", validators=[DataRequired()])
    last_name = StringField("Last name", validators=[DataRequired()])
    date_of_birth = DateField("Date of birth", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired(), Email()])
    phone_number = StringField("Phone number", validators=[DataRequired(), Length(max = 11)])
    
    text_area_field = TextAreaField("Reason:")
    submit = SubmitField("Submit")

class RegisterDoctor(Register):
    specialization = SelectMultipleField("Specialization", choices=doctor_specialties, validators=[DataRequired()])
    spec = SelectField("Specialization", choices=doctor_specialties, validators=[DataRequired()])
    dyploma = FileField("Dyploma", validators=[DataRequired()])
    personal_ID = FileField("Personal ID", validators=[DataRequired()])
    working_hours = StringField("Working hours:", validators=[DataRequired()], render_kw={"placeholder":"Example: 8-16"})

    contact = SubmitField("Contact")
    

class LoginForm(FlaskForm):
    role = SelectField("Role", choices=[("patient", "Patient"), ("doctor", "Doctor"), ("admin", "Admin")], validators=[DataRequired()])
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Remember me")

    submit = SubmitField("Login")
    register_doctor = SubmitField("Register as a doctor")
    register_patient = SubmitField("Register as a patient")

    redirect_not_verified_doctors = SubmitField("Not verified doctors")
    redirect_reported_users = SubmitField("Reported users")

    appointments = SubmitField("Appointments")
    doctors_list = SubmitField("List of doctors")
    logout = SubmitField("Log out")

    verify = SubmitField("Verify")
    reject = SubmitField("Reject")

class AppointmentForm(FlaskForm):
    appointment = SelectField("Select your appointment date:", validators=[DataRequired()], choices = None)

    submit = SubmitField("Submit")

class AppointmentActionForm(FlaskForm):
    delete_appointment = SubmitField("Delete")
    update_appointment = SubmitField("Update")

    submit = SubmitField("Submit")


@app.route("/register_doctor", methods=["GET", "POST"])
def register_doctor() -> str:
    form = RegisterDoctor()

    if form.submit.data:
        print("Data submitted")
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        
        file = request.files["dyploma"]
        file_2 = request.files["personal_ID"]

        dyploma = base64.b64encode(file.read())
        personal_ID = base64.b64encode(file_2.read())

        new_doctor = Doctor(
            username = form.username.data,
            password = hashed_pw,
            fname = form.first_name.data,
            lname = form.last_name.data,
            date_of_birth = form.date_of_birth.data,
            email = form.email.data,
            phone_number = form.phone_number.data,
            specialization = form.specialization.data,
            dyploma = dyploma,
            working_hours = form.working_hours.data,
            personal_ID = personal_ID)
        
        db.session.add(new_doctor)
        db.session.commit()
        return redirect(url_for("doctor_view"))
    
    return render_template("register_doctor.html",
                           title = "Register as a doctor",
                           form = form)

@app.route("/register_patient", methods=["GET", "POST"])
def register_patient() -> str:
    form = Register()

    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode("utf-8")

        new_patient = Patient(
            username = form.username.data,
            password = hashed_pw,
            fname = form.first_name.data,
            lname = form.last_name.data,
            date_of_birth = form.date_of_birth.data,
            email = form.email.data,
            phone_number = form.phone_number.data)

        db.session.add(new_patient)
        db.session.commit()
        return redirect(url_for("login"))

    return render_template("register_patient.html",
                            title = "Register as a patient",
                            form = form)

@app.route("/")
@app.route("/login", methods=["GET", "POST"])
def login() -> str:
    form = LoginForm()

    if form.validate_on_submit():
        if form.register_doctor.data:
            return redirect(url_for("register_doctor"))
        
        elif form.register_patient.data:
            return redirect(url_for("register_patient"))
        
        else:
            if form.role.data == "patient":
                patient = Patient.query.filter_by(username = form.username.data).first()

                if patient and bcrypt.check_password_hash(patient.password, form.password.data):
                    login_user(patient, remember = form.remember_me.data)

                    patient.active = True
                    db.session.commit()

                    return redirect(url_for("patient_view",
                                            id = current_user.id))

            elif form.role.data == "doctor":
                doctor = Doctor.query.filter_by(username = form.username.data).first()

                if doctor and bcrypt.check_password_hash(doctor.password, form.password.data):
                    login_user(doctor, remember = form.remember_me.data)

                    doctor.active = True
                    db.session.commit()

                    return redirect(url_for("doctor_view"))

            else:
                admin = Admin.query.filter_by(username = form.username.data).first()

                if admin and bcrypt.check_password_hash(admin.password, form.password.data):
                    login_user(admin)

                    admin.active = True
                    db.session.commit()

                    return redirect(url_for("admin_view"))

    return render_template("login.html",
                           title = "Log in",
                           form = form)

@login_required
@app.route("/patient_view_<int:id>", methods=["GET", "POST"])
def patient_view(id) -> str:
    form = LoginForm()

    if form.validate_on_submit():
        if form.appointments.data:
            return redirect(url_for("patient_view_appointments"))

        elif form.doctors_list.data:
            return redirect(url_for("patient_view_doctors"))
        
        elif form.logout.data:
            logout_user()

    return render_template("patient_view.html",
                           title = "Patient view",
                           form = form)

@login_required
@app.route("/patient_view/doctors", methods=["GET", "POST"])
def patient_view_doctors() -> str:
    form = RegisterDoctor()
    doctors = Doctor.query.all()

    
    if form.submit.data:
        return redirect(url_for("patient_view_doctors_spec",
                                spec = form.spec.data))
        
    elif form.contact.data:
        return redirect(url_for("schedule_an_appointment"))

    return render_template("patient_view_doctors.html",
                           title = "Doctors",
                           doctor = doctors,
                           form = form)

@app.route("/patient_view/doctors_<string:spec>", methods=["GET", "POST"])
def patient_view_doctors_spec(spec):
    form = RegisterDoctor()

    doctors = Doctor.query.filter_by(specialization = spec)

    return render_template("patient_view_doctors.html",
                           title = "Doctors",
                           doctor = doctors,
                           form = form)


@login_required
@app.route("/patient_view/patient_<int:p_id>_doctor_<int:d_id>_schedule_an_appointment", methods=["GET", "POST"])
def schedule_an_appointment(p_id, d_id) -> str:
    form = AppointmentForm()

    choices = dynamic_appointment_choices(d_id = d_id)
    form.appointment.choices = choices
    print(choices)

    if form.validate_on_submit():
        combined_datetime = form.appointment.data
        combined_datetime = datetime.datetime.strptime(
            combined_datetime, "%Y-%m-%d %H:%M")
        
        date = combined_datetime.date()
        time = str(int(combined_datetime.strftime("%H"))) 
        time.removeprefix("0")

        appointment = Appointment.query.filter(
            Appointment.doctor_id == d_id,
            Appointment.date == date,
            Appointment.hour == time
            ).first()

        if appointment:
            appointment.patient_id = current_user.id
            appointment.avaiable = False

            db.session.commit()

            return redirect(url_for("patient_view_appointments",
                                    id = current_user.id))

    return render_template("appointment.html",
                           title = "Schedule an appointment",
                           form = form)

@login_required
@app.route("/patient_view/patient_<int:id>_appointments", methods=["GET", "POST"])
def patient_view_appointments(id) -> str:
    form = AppointmentActionForm()

    appointments = Appointment.query.filter_by(
        patient_id = id)
    
    if form.validate_on_submit():
        if form.delete_appointment.data:
            return redirect(url_for("delete_appointment"))
        elif form.update_appointment.data:
            return redirect(url_for("update_appointment"))

    

    return render_template("patient_view_appointments.html",
                           title = "Appointments",
                           appointment = appointments,
                           form = form)

@login_required
@app.route("/patient_view/patient_<int:id>_delete_appointment<int:a_id>", methods=["GET", "POST"])
def delete_appointment(id, a_id) -> str:
    appointment = Appointment.query.get(a_id)

    if appointment:
        try:
            appointment.patient_id = None
            appointment.avaiable = True

            db.session.commit()
            return redirect(url_for("patient_view"))

        except Exception as e:
            print(f"Error {e}.")
            db.session.rollback()

    


@login_required
@app.route("/patient_view/patient_<int:id>_update_appointment<int:a_id>_doctor<int:d_id>", methods=["GET", "POST"])
def update_appointment(id, a_id, d_id) -> str:
    form_2 = AppointmentActionForm()
    form = AppointmentForm()

    choices = dynamic_appointment_choices(d_id = d_id)
    print(choices)
    form.appointment.choices = choices

    if form.validate_on_submit():
        combined_datetime = form.appointment.data
        combined_datetime = datetime.datetime.strptime(
            combined_datetime, "%Y-%m-%d %H:%M")
        
        date = combined_datetime.date()
        time = str(int(combined_datetime.strftime("%H"))) 
        time.removeprefix("0")

        appointment = Appointment.query.get(a_id)

        if appointment:
            appointment.date = date
            appointment.hour = time
        
            db.session.commit()

            return redirect(url_for("patient_view_appointments",
                            id = current_user.id))


    return render_template("appointment.html",
                           title = "Appointment",
                           d_id = d_id,
                           form = form)

@login_required
@app.route("/doctor_view", methods=["GET", "POST"])
def doctor_view() -> str:
    appointments = Appointment.query.filter(
        Appointment.doctor_id == current_user.id,
        Appointment.avaiable == False
    ).all()

    print(appointments)

    return render_template("doctor_view.html",
                               title = "Your schedule",
                               appointment = appointments)

@login_required
@app.route("/admin_view", methods=["GET", "POST"])
def admin_view() -> str:
    form = LoginForm()

    if form.validate_on_submit():
        if form.redirect_not_verified_doctors.data:
            return redirect(url_for("admin_view_not_verified_doctors"))
        
        elif form.redirect_reported_users.data:
            return redirect(url_for("admin_view_reported_users"))

    return render_template("admin_view.html",
                           title = "Admin View",
                           form = form)

@login_required
@app.route("/admin_view_not_verified_doctors", methods=["GET", "POST"])
def admin_view_not_verified_doctors() -> str:
    form = LoginForm()

    doctors_list = Doctor.query.all()

    if form.validate_on_submit():
        if form.verify.data:
            return redirect(url_for("admin_view_accept"))
        
        elif form.reject.data:
            return redirect(url_for("admin_view_reject"))

    return render_template("not_verified_doctors.html",
                           title = "Doctors waiting to verify.",
                           doctor = doctors_list,
                           form = form)

@app.route("/admin_view/accept_<int:d_id>", methods=["GET", "POST"])
def admin_view_accept(d_id) -> str:
    doctor = Doctor.query.get(d_id)

    try:
        doctor.verified = True
        db.session.commit()

        return redirect(url_for("admin_view"))
    
    except Exception as e:
        print(f"Error {e}.")

@app.route("/admin_view/reject_<int:d_id>", methods=["GET", "POST"])
def admin_view_reject(d_id) -> str:
    doctor = Doctor.query.get(d_id)

    try:
        db.session.delete(doctor)
        db.session.commit()

    except Exception as e:
        print(f"Error {e}.")


@login_manager.user_loader
def load_user(user_id):
    try:
        patient = Patient.query.get(int(user_id))
        if patient:
            return patient
        
    except Exception as e:
        print(f"Error: {e}.")

    try:
        doctor = Doctor.query.get(int(user_id))
        if doctor:
            return doctor
        
    except Exception as e:
        print(f"Error: {e}.")

    try:
        admin = Admin.query.get(int(user_id))
        if admin:
            return admin
        
    except Exception as e:
        print(f"Error: {e}.")

    return None

def dynamic_appointment_choices(d_id) -> list:
    date = datetime.datetime.today() + datetime.timedelta(days = 1)
    date_time = datetime.datetime.now().time()
    

    output = Appointment.query.filter(
        Appointment.doctor_id == d_id,
        Appointment.avaiable == True,
        Appointment.date >= date,
    ).all()

    output = list(output)
    print(output)

    choices = [(datetime.datetime.combine(slot.date, datetime.time(int(slot.hour), 0, 0))
                    .strftime('%Y-%m-%d %H:%M'), 
                datetime.datetime.combine(slot.date, datetime.time(int(slot.hour), 0, 0))
                    .strftime('%Y-%m-%d %H:%M'))
               for slot in output]

    return choices


def add_admin(username, password, fname, lname, date_of_birth, email, phone_number):
    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")

    new_admin = Admin(
        username = username,
        password = hashed_pw,
        fname = fname,
        lname = lname,
        date_of_birth = date_of_birth,
        email = email,
        phone_number = phone_number)
    
    db.session.add(new_admin)
    db.session.commit()

def row_generator():
    """Every week, function generates rows in the DataBase in Appointment table.
    
    I did not include any "Doctor took a vacation", or "Doctor doesn't work in that day",
    because I consider it to be useless in showcase portfolio project.
    
    In my opinion it is much useless code because gaining information about
    which days in a week doctor works is a simple Field and save it in the DB.
    Next, just take that into a consideration when generating rows.
     
    It is portfolio project. I care about the effectiveness, not much code that
    does not prove much. """


    row_amount = Doctor.query.count()
    x = 0
    doctor = Doctor.query.get(x + 1)

    todays_date = datetime.datetime.today()
    working_hours = str(doctor.working_hours)
    list = working_hours.split("-")

    a = int(list[0])
    b = int(list[1])

    while x != row_amount:
        for _ in range(5):
            for _ in range(8):
                appointment = Appointment(
                    doctor_id = doctor.id,
                    date = todays_date.strftime("%Y-%m-%d"),
                    hour = a)
                    
                a += 1

                db.session.add(appointment)
                db.session.commit()
            a -= 8
            todays_date += datetime.timedelta(days = 1)
            print(todays_date)
        break

if __name__ == "__main__":
    app.run()
