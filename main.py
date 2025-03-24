from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///employees.db'
app.config['JWT_SECRET_KEY'] = 'your_secret_key'  # Change this to a secure secret key
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Token expires in 1 hour

# Add CORS middleware
CORS(app, supports_credentials=True)

db = SQLAlchemy(app)
jwt = JWTManager(app)


# Employee Model
class Employee(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    level = db.Column(db.Integer, nullable=False)
    reportsTo = db.Column(db.Integer, db.ForeignKey('employee.id'))
    skills = db.Column(db.String(200), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    def __repr__(self):
        return f"Employee(id={self.id}, name={self.name}, role={self.role})"


class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    empId = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(10), nullable=False)

    __table_args__ = (
        db.UniqueConstraint('empId', 'date', name='uq_emp_date'),
        db.CheckConstraint("status IN ('PRESENT', 'ABSENT')", name='chk_status')
    )

    def __repr__(self):
        return f"Attendance(empId={self.empId}, date={self.date}, status={self.status})"


with app.app_context():
    db.create_all()


def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        api_key = request.headers.get("x-api-key")

        # API Key Authentication
        if api_key == "abcdef":
            return fn(*args, **kwargs)

        current_user_id = get_jwt_identity()  # Get the user ID from JWT
        if not current_user_id:
            return jsonify({"error": "Unauthorized"}), 401

        try:
            employee = Employee.query.get(int(current_user_id))  # Convert to integer for DB lookup
            if not employee:
                return jsonify({"error": "Unauthorized"}), 401
        except Exception as e:
            return jsonify({"error": str(e)}), 401

        return fn(*args, **kwargs)

    return wrapper


# API to log in and get a JWT token
@app.route('/login', methods=['POST'])
def login():
    if request.headers.get("x-api-key") != "abcdef": return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    email = data.get('email')
    password = data.get('password')

    employee = Employee.query.filter_by(email=email).first()
    if not employee or not check_password_hash(employee.password_hash, password):
        return jsonify({"error": "Invalid email or password"}), 401

    # Convert ID to string when creating JWT
    access_token = create_access_token(identity=str(employee.id))
    return jsonify({"token": access_token, "message": "Login successful"}), 200


# API to register an employee
@app.route('/register', methods=['POST'])
def register_employee():
    if request.headers.get("x-api-key") != "abcdef": return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    hashed_password = generate_password_hash(data['password'])

    try:
        employee = Employee(
            name=data['name'],
            email=data['email'],
            phone=data['phone'],
            role=data['role'],
            level=data['level'],
            reportsTo=data.get('reportsTo'),
            skills=data['skills'],
            password_hash=hashed_password
        )
        db.session.add(employee)
        db.session.commit()
        return jsonify({"message": "Employee registered successfully", "id": employee.id}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# API to get an employee by ID (Protected)
@app.route('/employees/<int:emp_id>', methods=['GET'])
@admin_required
def get_employee_by_id(emp_id):
    employee = Employee.query.get(emp_id)
    if not employee:
        return jsonify({"error": "Employee not found"}), 404

    return jsonify({
        "id": employee.id,
        "name": employee.name,
        "email": employee.email,
        "phone": employee.phone,
        "role": employee.role,
        "level": employee.level,
        "reportsTo": employee.reportsTo,
        "skills": employee.skills
    })


# API to get all employees (Protected)
@app.route('/employees', methods=['GET'])
@admin_required
def get_all_employees():
    employees = Employee.query.all()
    response = [
        {
            "id": emp.id,
            "name": emp.name,
            "email": emp.email,
            "phone": emp.phone,
            "role": emp.role,
            "level": emp.level,
            "reportsTo": emp.reportsTo,
            "skills": emp.skills
        }
        for emp in employees
    ]
    return jsonify(response)


# API to update an employee (Protected)
@app.route('/employees/<int:emp_id>', methods=['PUT'])
@admin_required
def update_employee(emp_id):
    data = request.json
    employee = Employee.query.get(emp_id)
    if not employee:
        return jsonify({"error": "Employee not found"}), 404

    try:
        for key, value in data.items():
            if key == "password":
                setattr(employee, "password_hash", generate_password_hash(value))
            else:
                setattr(employee, key, value)

        db.session.commit()
        return jsonify({"message": "Employee updated successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# API to delete an employee (Protected)
@app.route('/employees/<int:emp_id>', methods=['DELETE'])
def delete_employee(emp_id):
    if request.headers.get("x-api-key") != "abcdef": return jsonify({"error": "Unauthorized"}), 401
    employee = Employee.query.get(emp_id)
    if not employee:
        return jsonify({"error": "Employee not found"}), 404

    try:
        db.session.delete(employee)
        db.session.commit()
        return jsonify({"message": "Employee deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/employees/bulk-register', methods=['POST'])
def bulk_register_employees():
    if request.headers.get("x-api-key") != "abcdef": return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    employees = data.get('employees', [])
    if not employees:
        return jsonify({"error": "No employees provided"}), 400

    try:
        new_employees = []
        for emp in employees:
            hashed_password = generate_password_hash(emp['password'])
            new_employee = Employee(
                name=emp['name'],
                email=emp['email'],
                phone=emp['phone'],
                role=emp['role'],
                level=emp['level'],
                reportsTo=emp.get('reportsTo'),
                skills=emp['skills'],
                password_hash=hashed_password
            )
            new_employees.append(new_employee)

        db.session.bulk_save_objects(new_employees)
        db.session.commit()
        return jsonify({"message": "Employees registered successfully"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400


# API to add or update attendance (Protected)
@app.route('/attendance', methods=['POST'])
@admin_required
def add_or_update_attendance():
    data = request.json
    try:
        formatted_date = datetime.strptime(data['date'], "%Y-%m-%d").date()
        existing_record = Attendance.query.filter_by(empId=data['empId'], date=formatted_date).first()

        if existing_record and existing_record.status == data['status']:
            message = "Attendance updated successfully"
        elif existing_record and existing_record.status != data['status']:
            existing_record.status = data['status'].upper()
            message = "Attendance record added successfully"
        else:
            attendance = Attendance(
                empId=data['empId'],
                date=formatted_date,
                status=data['status'].upper()
            )
            db.session.add(attendance)
            message = "Attendance record added successfully"

        db.session.commit()
        return jsonify({"message": message}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# # API to get attendance records (Protected)
# @app.route('/attendance/<int:emp_id>', methods=['GET'])
# @admin_required
# def get_attendance(emp_id):
#     days = int(request.args.get('days', 1))
#     start_date = datetime.today().date() - timedelta(days=days - 1)
#
#     records = Attendance.query.filter(Attendance.empId == emp_id, Attendance.date >= start_date).all()
#
#     response = [
#         {"date": record.date.strftime("%Y-%m-%d"), "status": record.status}
#         for record in records
#     ]
#
#     return jsonify(response)

@app.route('/attendance/<int:emp_id>', methods=['POST'])
@admin_required
def get_attendance(emp_id):
    print("attendance_by_status")
    days = int(request.args.get('days', 1))
    start_date = datetime.today().date() - timedelta(days=days - 1)

    # Fetch attendance records for the employee within the specified date range
    records = Attendance.query.filter(Attendance.empId == emp_id, Attendance.date >= start_date).all()

    # Initialize a dictionary to group dates by status
    attendance_by_status = {"PRESENT": [], "ABSENT": []}

    # Populate the dictionary with dates based on status
    for record in records:
        if record.status == "PRESENT":
            attendance_by_status["PRESENT"].append(record.date.strftime("%Y-%m-%d"))
        elif record.status == "ABSENT":
            attendance_by_status["ABSENT"].append(record.date.strftime("%Y-%m-%d"))

    print("attendance_by_status", attendance_by_status)
    return jsonify(attendance_by_status)


# API to delete an attendance record (Protected)
@app.route('/attendance/<int:emp_id>', methods=['DELETE'])
@admin_required
def delete_attendance(emp_id):
    date_str = request.args.get('date')

    if not date_str:
        return jsonify({"error": "Date parameter is required"}), 400

    try:
        # Convert date string to Date object
        date_obj = datetime.strptime(date_str, "%Y-%m-%d").date()

        # Find the attendance record
        attendance = Attendance.query.filter_by(empId=emp_id, date=date_obj).first()
        if not attendance:
            return jsonify({"error": "Attendance record not found"}), 404

        # Delete the record
        db.session.delete(attendance)
        db.session.commit()

        return jsonify({"message": "Attendance record deleted successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/attendance/bulk-add', methods=['POST'])
def bulk_add_attendance():
    if request.headers.get("x-api-key") != "abcdef": return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    attendance_records = data.get('attendance', [])
    if not attendance_records:
        return jsonify({"error": "No attendance records provided"}), 400

    try:
        new_records = []
        for record in attendance_records:
            formatted_date = datetime.strptime(record['date'], "%Y-%m-%d").date()
            new_attendance = Attendance(
                empId=record['empId'],
                date=formatted_date,
                status=record['status'].upper()
            )
            new_records.append(new_attendance)

        db.session.bulk_save_objects(new_records)
        db.session.commit()
        return jsonify({"message": "Attendance records added successfully"}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400


# API to execute custom queries
@app.route('/query', methods=['POST'])
def execute_query():
    if request.headers.get("x-api-key") != "abcdef": return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    query = data.get('query')

    if not query:
        return jsonify({"error": "Query is required"}), 400

    try:
        # Execute the raw SQL query
        result = db.session.execute(text(query))
        db.session.commit()

        # Fetch results if it's a SELECT query
        if result.returns_rows:
            rows = result.fetchall()
            # Convert rows to a list of dictionaries
            response = [dict(row._mapping) for row in rows]
            return jsonify(response)
        else:
            return jsonify({"message": "Query executed successfully"}), 200

    except Exception as e:
        # Handle any errors during query execution
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(port=5003, debug=True)
