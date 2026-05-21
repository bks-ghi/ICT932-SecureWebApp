from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_login import LoginManager, login_required, current_user, logout_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from models import db, User, Student, Course, Enrollment, Grade, Attendance, AuditLog
from logger import setup_logger
from auth.login import handle_login, handle_register, handle_2fa
from datetime import datetime
import bleach
import os


logger = setup_logger()

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get(
    'SECRET_KEY',
    'ict932-secret-key-change-in-production'
)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///secureapp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# -------------------------------------------------
# Secure Cookie Configuration - ZAP Remediation
# -------------------------------------------------

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Keep False for localhost HTTP testing.
# In real HTTPS production, change this to True.
app.config['SESSION_COOKIE_SECURE'] = False

db.init_app(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# -------------------------------------------------
# Helper Functions
# -------------------------------------------------

def clean_text(value):
    return bleach.clean(value or '').strip()


def is_admin():
    return current_user.is_authenticated and current_user.role == 'admin'


def is_teacher():
    return current_user.is_authenticated and current_user.role == 'teacher'


def is_student():
    return current_user.is_authenticated and current_user.role == 'student'


def can_manage_academic_records():
    return current_user.is_authenticated and current_user.role in ['admin', 'teacher']


def can_view_academic_records():
    return current_user.is_authenticated and current_user.role in ['admin', 'teacher', 'student']


def get_current_student_record():
    if not current_user.is_authenticated:
        return None

    student = Student.query.filter_by(email=current_user.email).first()

    if not student:
        student = Student.query.filter_by(student_id=current_user.username).first()

    return student


def sync_registered_students():
    """
    If someone registers as a student user account,
    this creates a matching Student profile automatically
    so they appear in Enroll, Grades, Attendance pages.
    """
    student_users = User.query.filter_by(role='student').all()

    for user in student_users:
        existing_student = Student.query.filter_by(email=user.email).first()

        if not existing_student:
            student_id = user.username

            duplicate_id = Student.query.filter_by(student_id=student_id).first()
            if duplicate_id:
                student_id = f"user{user.id}"

            new_student = Student(
                student_id=student_id,
                full_name=user.username,
                email=user.email,
                phone=''
            )

            db.session.add(new_student)

    db.session.commit()


def log_action(action):
    try:
        log = AuditLog(
            user_id=current_user.id if current_user.is_authenticated else None,
            action=action,
            ip_address=request.remote_addr
        )

        db.session.add(log)
        db.session.commit()

    except Exception as e:
        db.session.rollback()
        print(f"Audit log error: {e}")


# -------------------------------------------------
# Security Headers - ZAP Remediation
# -------------------------------------------------

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )

    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'

    # Older browser protection. Modern browsers mainly rely on CSP,
    # but this is fine for assignment evidence.
    response.headers['X-XSS-Protection'] = '1; mode=block'

    return response


# -------------------------------------------------
# Authentication Routes
# -------------------------------------------------

@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    return handle_login()


@app.route('/register', methods=['GET', 'POST'])
def register():
    return handle_register()


@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    return handle_2fa()


@app.route('/setup-2fa/<int:user_id>')
def setup_2fa(user_id):
    import pyotp
    import qrcode
    import base64
    from io import BytesIO

    user = User.query.get_or_404(user_id)

    otp_uri = pyotp.totp.TOTP(user.totp_secret).provisioning_uri(
        name=user.email,
        issuer_name="Secure Student Management System"
    )

    qr = qrcode.make(otp_uri)
    buffer = BytesIO()
    qr.save(buffer, format="PNG")

    qr_code = base64.b64encode(buffer.getvalue()).decode()

    return render_template(
        'setup_2fa.html',
        user=user,
        qr_code=qr_code,
        secret=user.totp_secret
    )


@app.route('/logout')
@login_required
def logout():
    username = current_user.username

    log_action(f"User logged out: {username}")

    logout_user()

    # Clear old flash messages so they do not appear on login page
    session.pop('_flashes', None)

    flash('You have been logged out successfully.', 'success')
    logger.info(f"User {username} logged out")

    return redirect(url_for('login'))


# -------------------------------------------------
# Dashboard
# -------------------------------------------------

@app.route('/dashboard')
@login_required
def dashboard():
    log_action("Viewed dashboard")
    return render_template('dashboard.html', user=current_user)


# -------------------------------------------------
# Admin Panel
# -------------------------------------------------

@app.route('/admin')
@login_required
def admin():
    if not is_admin():
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('dashboard'))

    users = User.query.all()

    log_action("Viewed admin panel")

    return render_template('admin.html', users=users)


@app.route('/admin/update-role/<int:user_id>', methods=['POST'])
@login_required
def update_user_role(user_id):
    if not is_admin():
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    new_role = request.form.get('role')

    if new_role not in ['admin', 'teacher', 'student']:
        flash('Invalid role selected.', 'danger')
        return redirect(url_for('admin'))

    old_role = user.role
    user.role = new_role

    db.session.commit()

    sync_registered_students()

    log_action(f"Updated role for {user.username} from {old_role} to {new_role}")
    flash(f"Role updated for {user.username}.", 'success')

    return redirect(url_for('admin'))


@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not is_admin():
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash('You cannot delete your own admin account.', 'danger')
        return redirect(url_for('admin'))

    username = user.username

    db.session.delete(user)
    db.session.commit()

    log_action(f"Deleted user account: {username}")
    flash(f"User {username} deleted successfully.", 'success')

    return redirect(url_for('admin'))


# -------------------------------------------------
# Students
# -------------------------------------------------

@app.route('/students')
@login_required
def students():
    if current_user.role not in ['admin', 'teacher']:
        flash('Access denied. Only admin and teacher can view students.', 'danger')
        return redirect(url_for('dashboard'))

    sync_registered_students()

    all_students = Student.query.all()

    log_action("Viewed students list")

    return render_template('students.html', students=all_students)


@app.route('/students/add', methods=['GET', 'POST'])
@login_required
def add_student():
    if not is_admin():
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        student_id = clean_text(request.form.get('student_id'))
        full_name = clean_text(request.form.get('full_name'))
        email = clean_text(request.form.get('email'))
        phone = clean_text(request.form.get('phone'))

        if Student.query.filter_by(student_id=student_id).first():
            flash('Student ID already exists.', 'danger')
            return redirect(url_for('add_student'))

        student = Student(
            student_id=student_id,
            full_name=full_name,
            email=email,
            phone=phone
        )

        db.session.add(student)
        db.session.commit()

        log_action(f"Added student record: {student_id}")
        flash('Student added successfully!', 'success')

        return redirect(url_for('students'))

    return render_template('add_student.html')


@app.route('/students/edit/<int:student_id>', methods=['GET', 'POST'])
@login_required
def edit_student(student_id):
    if not is_admin():
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('students'))

    student = Student.query.get_or_404(student_id)

    if request.method == 'POST':
        student.student_id = clean_text(request.form.get('student_id'))
        student.full_name = clean_text(request.form.get('full_name'))
        student.email = clean_text(request.form.get('email'))
        student.phone = clean_text(request.form.get('phone'))

        db.session.commit()

        log_action(f"Updated student record: {student.student_id}")
        flash('Student updated successfully.', 'success')

        return redirect(url_for('students'))

    return render_template('edit_student.html', student=student)


@app.route('/students/delete/<int:student_id>', methods=['POST'])
@login_required
def delete_student(student_id):
    if not is_admin():
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('students'))

    student = Student.query.get_or_404(student_id)
    deleted_student_id = student.student_id

    Enrollment.query.filter_by(student_id=student.id).delete()
    Grade.query.filter_by(student_id=student.id).delete()
    Attendance.query.filter_by(student_id=student.id).delete()

    db.session.delete(student)
    db.session.commit()

    log_action(f"Deleted student record: {deleted_student_id}")
    flash('Student deleted successfully.', 'success')

    return redirect(url_for('students'))


@app.route('/add-student')
@login_required
def old_add_student_redirect():
    return redirect(url_for('add_student'))


# -------------------------------------------------
# Courses
# -------------------------------------------------

@app.route('/courses')
@login_required
def courses():
    all_courses = Course.query.all()

    log_action("Viewed courses list")

    return render_template('courses.html', courses=all_courses)


@app.route('/courses/add', methods=['GET', 'POST'])
@login_required
def add_course():
    if not is_admin():
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        code = clean_text(request.form.get('course_code'))
        name = clean_text(request.form.get('course_name'))
        description = clean_text(request.form.get('description'))

        if Course.query.filter_by(course_code=code).first():
            flash('Course code already exists.', 'danger')
            return redirect(url_for('add_course'))

        course = Course(
            course_code=code,
            course_name=name,
            description=description
        )

        db.session.add(course)
        db.session.commit()

        log_action(f"Added course: {code}")
        flash('Course added successfully!', 'success')

        return redirect(url_for('courses'))

    return render_template('add_course.html')


@app.route('/courses/edit/<int:course_id>', methods=['GET', 'POST'])
@login_required
def edit_course(course_id):
    if not is_admin():
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('courses'))

    course = Course.query.get_or_404(course_id)

    if request.method == 'POST':
        course.course_code = clean_text(request.form.get('course_code'))
        course.course_name = clean_text(request.form.get('course_name'))
        course.description = clean_text(request.form.get('description'))

        db.session.commit()

        log_action(f"Updated course: {course.course_code}")
        flash('Course updated successfully.', 'success')

        return redirect(url_for('courses'))

    return render_template('edit_course.html', course=course)


@app.route('/courses/delete/<int:course_id>', methods=['POST'])
@login_required
def delete_course(course_id):
    if not is_admin():
        flash('Access denied. Admin only.', 'danger')
        return redirect(url_for('courses'))

    course = Course.query.get_or_404(course_id)
    deleted_course_code = course.course_code

    Enrollment.query.filter_by(course_id=course.id).delete()
    Grade.query.filter_by(course_id=course.id).delete()
    Attendance.query.filter_by(course_id=course.id).delete()

    db.session.delete(course)
    db.session.commit()

    log_action(f"Deleted course: {deleted_course_code}")
    flash('Course deleted successfully.', 'success')

    return redirect(url_for('courses'))


# -------------------------------------------------
# Enrollment
# -------------------------------------------------

@app.route('/enroll', methods=['GET', 'POST'])
@login_required
def enroll():
    if current_user.role not in ['admin', 'teacher']:
        flash('Access denied. Only admin and teacher can enroll students.', 'danger')
        return redirect(url_for('dashboard'))

    sync_registered_students()

    all_students = Student.query.all()
    all_courses = Course.query.all()

    if request.method == 'POST':
        student_id = request.form.get('student_id')
        course_id = request.form.get('course_id')

        existing = Enrollment.query.filter_by(
            student_id=student_id,
            course_id=course_id
        ).first()

        if existing:
            flash('Student is already enrolled in this course.', 'warning')
        else:
            enrollment = Enrollment(
                student_id=student_id,
                course_id=course_id
            )

            db.session.add(enrollment)
            db.session.commit()

            log_action(f"Enrolled student ID {student_id} in course ID {course_id}")
            flash('Student enrolled successfully!', 'success')

        return redirect(url_for('enroll'))

    return render_template(
        'enroll.html',
        students=all_students,
        courses=all_courses
    )


# -------------------------------------------------
# Grades
# -------------------------------------------------

@app.route('/grades', methods=['GET', 'POST'])
@login_required
def grades():
    if not can_view_academic_records():
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    sync_registered_students()

    all_students = Student.query.all()
    all_courses = Course.query.all()

    if request.method == 'POST':
        if not can_manage_academic_records():
            flash('Only admin and teacher can record grades.', 'danger')
            return redirect(url_for('grades'))

        student_id = request.form.get('student_id')
        course_id = request.form.get('course_id')
        grade_value = clean_text(request.form.get('grade'))
        remarks = clean_text(request.form.get('remarks'))

        grade_record = Grade(
            student_id=student_id,
            course_id=course_id,
            grade=grade_value,
            remarks=remarks
        )

        db.session.add(grade_record)
        db.session.commit()

        log_action(f"Recorded grade for student ID {student_id}")
        flash('Grade recorded successfully!', 'success')

        return redirect(url_for('grades'))

    if is_student():
        student_record = get_current_student_record()

        if student_record:
            all_grades = Grade.query.filter_by(student_id=student_record.id).all()
        else:
            all_grades = []
    else:
        all_grades = Grade.query.all()

    log_action("Viewed grades page")

    return render_template(
        'grades.html',
        students=all_students,
        courses=all_courses,
        grades=all_grades
    )


@app.route('/grades/edit/<int:grade_id>', methods=['POST'])
@login_required
def edit_grade(grade_id):
    if not can_manage_academic_records():
        flash('Access denied. Admin and teacher only.', 'danger')
        return redirect(url_for('grades'))

    grade_record = Grade.query.get_or_404(grade_id)

    grade_record.student_id = request.form.get('student_id')
    grade_record.course_id = request.form.get('course_id')
    grade_record.grade = clean_text(request.form.get('grade'))
    grade_record.remarks = clean_text(request.form.get('remarks'))

    db.session.commit()

    log_action(f"Updated grade ID {grade_id}")
    flash('Grade updated successfully.', 'success')

    return redirect(url_for('grades'))


@app.route('/grades/delete/<int:grade_id>', methods=['POST'])
@login_required
def delete_grade(grade_id):
    if not can_manage_academic_records():
        flash('Access denied. Admin and teacher only.', 'danger')
        return redirect(url_for('grades'))

    grade_record = Grade.query.get_or_404(grade_id)

    db.session.delete(grade_record)
    db.session.commit()

    log_action(f"Deleted grade ID {grade_id}")
    flash('Grade deleted successfully.', 'success')

    return redirect(url_for('grades'))


# -------------------------------------------------
# Attendance
# -------------------------------------------------

@app.route('/attendance', methods=['GET', 'POST'])
@login_required
def attendance():
    if not can_view_academic_records():
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))

    sync_registered_students()

    all_students = Student.query.all()
    all_courses = Course.query.all()

    if request.method == 'POST':
        if not can_manage_academic_records():
            flash('Only admin and teacher can record attendance.', 'danger')
            return redirect(url_for('attendance'))

        student_id = request.form.get('student_id')
        course_id = request.form.get('course_id')
        date_value = request.form.get('date')
        status = clean_text(request.form.get('status', 'Present'))

        try:
            attendance_date = datetime.strptime(date_value, '%Y-%m-%d').date()
        except Exception:
            flash('Invalid date format.', 'danger')
            return redirect(url_for('attendance'))

        attendance_record = Attendance(
            student_id=student_id,
            course_id=course_id,
            date=attendance_date,
            status=status
        )

        db.session.add(attendance_record)
        db.session.commit()

        log_action(f"Marked attendance for student ID {student_id}")
        flash('Attendance recorded successfully!', 'success')

        return redirect(url_for('attendance'))

    if is_student():
        student_record = get_current_student_record()

        if student_record:
            all_attendance = Attendance.query.filter_by(student_id=student_record.id).all()
        else:
            all_attendance = []
    else:
        all_attendance = Attendance.query.all()

    log_action("Viewed attendance page")

    return render_template(
        'attendance.html',
        students=all_students,
        courses=all_courses,
        attendance=all_attendance,
        attendance_records=all_attendance
    )


@app.route('/attendance/edit/<int:attendance_id>', methods=['POST'])
@login_required
def edit_attendance(attendance_id):
    if not can_manage_academic_records():
        flash('Access denied. Admin and teacher only.', 'danger')
        return redirect(url_for('attendance'))

    attendance_record = Attendance.query.get_or_404(attendance_id)

    attendance_record.student_id = request.form.get('student_id')
    attendance_record.course_id = request.form.get('course_id')
    attendance_record.status = clean_text(request.form.get('status'))

    date_value = request.form.get('date')

    try:
        attendance_record.date = datetime.strptime(date_value, '%Y-%m-%d').date()
    except Exception:
        flash('Invalid date format.', 'danger')
        return redirect(url_for('attendance'))

    db.session.commit()

    log_action(f"Updated attendance ID {attendance_id}")
    flash('Attendance updated successfully.', 'success')

    return redirect(url_for('attendance'))


@app.route('/attendance/delete/<int:attendance_id>', methods=['POST'])
@login_required
def delete_attendance(attendance_id):
    if not can_manage_academic_records():
        flash('Access denied. Admin and teacher only.', 'danger')
        return redirect(url_for('attendance'))

    attendance_record = Attendance.query.get_or_404(attendance_id)

    db.session.delete(attendance_record)
    db.session.commit()

    log_action(f"Deleted attendance ID {attendance_id}")
    flash('Attendance deleted successfully.', 'success')

    return redirect(url_for('attendance'))


# -------------------------------------------------
# Audit Logs
# -------------------------------------------------

@app.route('/audit-logs')
@login_required
def audit_logs():
    if not is_admin():
        flash('Access denied. Admins only.', 'danger')
        return redirect(url_for('dashboard'))

    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()

    for log in logs:
        log.event = getattr(log, 'action', '')

        if getattr(log, 'user_id', None):
            user = db.session.get(User, log.user_id)
            log.user = user.username if user else 'Deleted User'
        else:
            log.user = 'System'

    log_action("Viewed audit logs")

    return render_template('audit_logs.html', logs=logs)


# -------------------------------------------------
# Run App
# -------------------------------------------------

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    logger.info("Secure app started")

    app.run(
        debug=os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    )
