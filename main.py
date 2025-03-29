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
    clientCompany = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    employeeType = db.Column(db.String(100), nullable=False)
    reportsTo = db.Column(db.Integer, db.ForeignKey('employee.id'))
    skills = db.Column(db.String(200), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)

    __table_args__ = (
        db.CheckConstraint("employeeType IN ('A', 'B', 'C')", name='chk_employee_type'),
    )

    def __repr__(self):
        return f"Employee(id={self.id}, name={self.name}, role={self.role})"


class Attendance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    empId = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(10), nullable=False)
    requestId = db.Column(db.Integer, db.ForeignKey('request_approval.id'), nullable=True)  # New nullable field
    __table_args__ = (
        db.UniqueConstraint('empId', 'date', name='uq_emp_date'),
        db.CheckConstraint("status IN ('PRESENT', 'ABSENT', 'WFH')", name='chk_status')
    )

    def __repr__(self):
        return f"Attendance(empId={self.empId}, date={self.date}, status={self.status})"


class RequestApproval(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    requesterEmpId = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    approverEmpId = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    requestType = db.Column(db.String(100), nullable=False)
    requestStatus = db.Column(db.String(10), nullable=False)
    requestCreatedDate = db.Column(db.Date, nullable=False)
    fromDate = db.Column(db.Date, nullable=False)
    toDate = db.Column(db.Date, nullable=False)

    __table_args__ = (
        db.CheckConstraint("requestStatus IN ('PENDING', 'APPROVED', 'REJECTED')", name='chk_request_status'),
        db.CheckConstraint("requestType IN ('WFH', 'LEAVE')", name='chk_request_type')
    )

with app.app_context():
    db.create_all()


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        api_key = request.headers.get("x-api-key")

        # First try API Key Authentication
        if api_key == "abcdef":
            return fn(*args, **kwargs)

        # If no API key, try JWT
        try:
            jwt_required()(lambda: None)()  # This will verify the JWT
            current_user_id = get_jwt_identity()

            if not current_user_id:
                return jsonify({"error": "Unauthorized"}), 401

            employee = Employee.query.get(int(current_user_id))
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
    return jsonify({"token": access_token, "message": "Login successful", "empId": employee.id}), 200


# API to register an employee
@app.route('/register', methods=['POST'])
def register_employee():
    if request.headers.get("x-api-key") != "abcdef": return jsonify({"error": "Unauthorized"}), 401
    data = request.json
    hashed_password = generate_password_hash(data['password'])

    level = data['level']
    if (level < 0) or (level > 9): return jsonify({"error": "Invalid level"}), 401

    if level <= 3:
        employee_type = 'A'
    elif level <= 6:
        employee_type = 'B'
    else:
        employee_type = 'C'

    try:
        employee = Employee(
            name=data['name'],
            email=data['email'],
            phone=data['phone'],
            role=data['role'],
            level=level,
            reportsTo=data.get('reportsTo'),
            skills=data['skills'],
            employeeType=employee_type,
            clientCompany=data['clientCompany'],
            location=data['location'],
            password_hash=hashed_password
        )
        db.session.add(employee)
        db.session.commit()
        return jsonify({"message": "Employee registered successfully", "id": employee.id}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# API to get an employee by ID (Protected)
@app.route('/employees/<int:emp_id>', methods=['POST'])
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
        "skills": employee.skills,
        "employeeType": employee.employeeType,
        "clientCompany": employee.clientCompany,
        "location": employee.location
    })


# API to get all employees (Protected)
@app.route('/employees', methods=['POST'])
@admin_required
def get_all_employees():
    phone_number = request.args.get("phone")
    if phone_number:
        employees = Employee.query.filter(Employee.phone == phone_number).all()
    else:
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
            "skills": emp.skills,
            "employeeType": emp.employeeType,
            "clientCompany": emp.clientCompany,
            "location": emp.location
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
            level = emp['level']
            if (level < 0) or (level > 9): return jsonify({"error": "Invalid level"}), 401

            if level <= 3:
                employee_type = 'A'
            elif level <= 6:
                employee_type = 'B'
            else:
                employee_type = 'C'
            hashed_password = generate_password_hash(emp['password'])
            new_employee = Employee(
                name=emp['name'],
                email=emp['email'],
                phone=emp['phone'],
                role=emp['role'],
                level=level,
                reportsTo=emp.get('reportsTo'),
                skills=emp['skills'],
                employeeType=employee_type,
                clientCompany=emp['clientCompany'],
                location=emp['location'],
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
            message = f"Attendance is already {data['status']}"
        elif existing_record and existing_record.status != data['status']:
            existing_record.status = data['status'].upper()
            message = f"Attendance record updated successfully to {data['status']}"
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
    days = int(request.args.get('days', 1))
    if request.args.get('from'):
        from_date = datetime.strptime(request.args.get('from'), '%Y-%m-%d').date()
    else:
        from_date = None

    if request.args.get('to'):
        to_date = datetime.strptime(request.args.get('to'), '%Y-%m-%d').date()
    else:
        to_date = None

    if from_date:
        start_date = from_date
    else:
        start_date = datetime.today().date() - timedelta(days=days - 1)

    if to_date:
        end_date = to_date
    else:
        end_date = datetime.today().date()
    # Fetch attendance records for the employee within the specified date range
    print(start_date, end_date)
    records = Attendance.query.filter(Attendance.empId == emp_id, Attendance.date >= start_date, Attendance.date <= end_date).all()

    # Initialize a dictionary to group dates by status
    attendance_by_status = {"PRESENT": [], "ABSENT": [], "WFH": []}

    # Populate the dictionary with dates based on status
    for record in records:
        if record.status == "PRESENT":
            attendance_by_status["PRESENT"].append(record.date.strftime("%Y-%m-%d"))
        elif record.status == "ABSENT":
            attendance_by_status["ABSENT"].append(record.date.strftime("%Y-%m-%d"))
        elif record.status == "WFH":
            attendance_by_status["WFH"].append(record.date.strftime("%Y-%m-%d"))

    # Calculate leave statistics based on ABSENT records in Attendance table
    current_year = datetime.today().year
    absent_records = Attendance.query.filter(
        Attendance.empId == emp_id,
        Attendance.status == 'ABSENT',
        db.extract('year', Attendance.date) == current_year
    ).all()

    # Calculate total leaves taken and monthly breakdown
    total_leaves = len(absent_records)
    monthly_leaves = {}

    for record in absent_records:
        month = record.date.month
        monthly_leaves.setdefault(month, 0)
        monthly_leaves[month] += 1

    # Add remaining leave balance
    remaining_leaves = max(0, 24 - total_leaves)

    # Prepare response
    response = {
        "attendance": attendance_by_status,
        "leave_stats": {
            "total_leaves_taken": total_leaves,
            "monthly_leaves": monthly_leaves,
            "remaining_leaves": remaining_leaves,
            "max_allowed_leaves": 24
        }
    }
    return jsonify(response)


@app.route('/<int:emp_id>/attendance_by_date', methods=['POST'])
@admin_required
def get_attendance_by_date(emp_id):
    date = request.args.get('date')
    formatted_date = datetime.strptime(date, "%Y-%m-%d").date()
    # Fetch attendance records for the employee within the specified date range
    records = Attendance.query.filter(Attendance.empId == emp_id, Attendance.date == formatted_date).all()

    print(records)
    if records:
        return jsonify({"attendance": records[0].status}), 200
    else:
        return jsonify({"error": "Attendance record not found"}), 400


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


@app.route('/attendance/search', methods=['POST'])
@admin_required
def search_attendance():
    try:
        data = request.json
        emp_ids = data.get('empIds', [])
        client_company = data.get('clientCompany')
        location = data.get('location')
        reports_to = data.get('reportsTo')
        from_date = datetime.strptime(data.get('fromDate', '1900-01-01'), "%Y-%m-%d").date()
        to_date = datetime.strptime(data.get('toDate', '2100-12-31'), "%Y-%m-%d").date()

        # Build employee query
        employee_query = Employee.query

        if emp_ids:
            employee_query = employee_query.filter(Employee.id.in_(emp_ids))
        if client_company:
            employee_query = employee_query.filter(Employee.clientCompany == client_company)
        if location:
            employee_query = employee_query.filter(Employee.location == location)
        if reports_to:
            employee_query = employee_query.filter(Employee.reportsTo == reports_to)

        employees = employee_query.all()

        current_year = datetime.today().year
        response = []

        for employee in employees:
            # Get attendance records for the date range
            attendance_records = Attendance.query.filter(
                Attendance.empId == employee.id,
                Attendance.date.between(from_date, to_date)
            ).all()

            # Initialize counts
            present_days = 0
            absent_days = 0
            wfh_days = 0

            # Count statuses
            for record in attendance_records:
                if record.status == "PRESENT":
                    present_days += 1
                elif record.status == "ABSENT":
                    absent_days += 1
                elif record.status == "WFH":
                    wfh_days += 1

            # Calculate leaves taken this year (from ABSENT records)
            leaves_taken = Attendance.query.filter(
                Attendance.empId == employee.id,
                Attendance.status == 'ABSENT',
                db.extract('year', Attendance.date) == current_year
            ).count()

            remaining_leaves = max(0, 24 - leaves_taken)

            response.append({
                "empId": employee.id,
                "name": employee.name,
                "clientCompany": employee.clientCompany,
                "location": employee.location,
                "reportsTo": employee.reportsTo,
                "attendance": {
                    "PRESENT": present_days,
                    "ABSENT": absent_days,
                    "WFH": wfh_days,
                    "totalDays": (to_date - from_date).days + 1
                },
                "leaveStats": {
                    "leavesTaken": leaves_taken,
                    "remainingLeaves": remaining_leaves,
                    "maxAllowedLeaves": 24
                }
            })

        return jsonify(response), 200

    except Exception as e:
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


# API to create a new request approval with conflict checking
# Modified create_request_approval function to check leave limits
@app.route('/request-approvals', methods=['POST'])
@admin_required
def create_request_approval():
    try:
        data = request.json
        emp_id = data.get('empId')
        request_type = data.get('requestType')
        from_date = datetime.strptime(data.get('fromDate'), "%Y-%m-%d").date()
        to_date = datetime.strptime(data.get('toDate'), "%Y-%m-%d").date()

        # Validate date range
        if from_date > to_date:
            return jsonify({"error": "Invalid date range"}), 400

        # For LEAVE requests, check if employee has remaining leave balance
        if request_type == 'LEAVE':
            current_year = datetime.today().year

            # Calculate total ABSENT days in current year from Attendance table
            absent_days = Attendance.query.filter(
                Attendance.empId == emp_id,
                Attendance.status == 'ABSENT',
                db.extract('year', Attendance.date) == current_year
            ).count()

            # Calculate pending leave days from PENDING requests
            pending_leaves = RequestApproval.query.filter(
                RequestApproval.requesterEmpId == emp_id,
                RequestApproval.requestType == 'LEAVE',
                RequestApproval.requestStatus == 'PENDING',
                db.extract('year', RequestApproval.fromDate) == current_year
            ).all()

            total_pending_leaves = sum(
                (req.toDate - req.fromDate).days + 1
                for req in pending_leaves
            )

            # Calculate requested leave days
            requested_days = (to_date - from_date).days + 1

            # Check if total would exceed 15 days
            if absent_days + total_pending_leaves + requested_days > 15:
                return jsonify({
                    "error": "Leave limit exceeded, Check already leaves",
                    "message": f"You have {15 - absent_days - total_pending_leaves} leaves remaining, and total_pending_leaves {total_pending_leaves}",
                    "leaves_taken": absent_days,
                    "pending_leaves": total_pending_leaves
                }), 400

        # Check for existing attendance conflicts
        existing_attendances = Attendance.query.filter(
            Attendance.empId == emp_id,
            Attendance.date.between(from_date, to_date)
        ).all()

        if existing_attendances:
            conflict_dates = [att.date.strftime("%Y-%m-%d") for att in existing_attendances]
            return jsonify({
                "error": "Attendance conflicts found",
                "conflictDates": conflict_dates,
                "message": "Cannot create request due to existing attendance records"
            }), 409

        existing_requests = RequestApproval.query.filter(
            RequestApproval.requesterEmpId == emp_id,
            RequestApproval.requestType == 'LEAVE',
            RequestApproval.requestStatus == 'PENDING',
            RequestApproval.fromDate >= from_date,
            RequestApproval.fromDate <= to_date,
        ).all()

        if existing_requests:
            return jsonify({
                "error": "Conflicts found with already applied leaves",
                "message": "Cannot create request due to existing conflicting approval requests"
            })

        # Get employee to find who they report to
        employee = Employee.query.get(emp_id)
        if not employee:
            return jsonify({"error": "Employee not found"}), 404

        # Create the request
        request_approval = RequestApproval(
            requesterEmpId=emp_id,
            approverEmpId=employee.reportsTo,
            requestType=request_type.upper(),
            requestStatus="PENDING",
            requestCreatedDate=datetime.today().date(),
            fromDate=from_date,
            toDate=to_date
        )

        db.session.add(request_approval)
        db.session.commit()

        return jsonify({
            "message": "Request created successfully",
            "requestId": request_approval.id
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400


# Enhanced API to update request status with conflict checking
@app.route('/request-approvals/<int:request_id>', methods=['PUT'])
@admin_required
def update_request_status(request_id):
    try:
        data = request.json
        new_status = data.get('requestStatus').upper()
        user_id = data.get('userId')

        if new_status not in ['APPROVED', 'REJECTED', 'PENDING']:
            return jsonify({"error": "Invalid status"}), 400

        request_approval = RequestApproval.query.get(request_id)
        if not request_approval:
            return jsonify({"error": "Request not found"}), 404

        if request_approval.requestStatus == "REJECTED":
            return jsonify({"error": "No operations allowed on rejected request"}), 409

        # Check if the current user is the approver
        current_user_id = user_id
        if int(current_user_id) != request_approval.approverEmpId:
            return jsonify({"error": "Unauthorized - Only approver can update status"}), 403

        # Handle approval with additional conflict checking
        if new_status == 'APPROVED':
            # Check for attendance conflicts that appeared after request creation
            existing_attendances = Attendance.query.filter(
                Attendance.empId == request_approval.requesterEmpId,
                Attendance.date.between(request_approval.fromDate, request_approval.toDate),
                Attendance.date >= request_approval.requestCreatedDate  # Only check conflicts after request was made
            ).all()

            if existing_attendances:
                conflict_dates = [att.date.strftime("%Y-%m-%d") for att in existing_attendances]
                return jsonify({
                    "error": "Cannot approve - attendance conflicts found",
                    "conflictDates": conflict_dates,
                    "message": "Please resolve conflicts before approving"
                }), 409

            # Add attendance records
            delta = request_approval.toDate - request_approval.fromDate
            for i in range(delta.days + 1):
                current_date = request_approval.fromDate + timedelta(days=i)

                attendance = Attendance(
                    empId=request_approval.requesterEmpId,
                    date=current_date,
                    status='WFH' if request_approval.requestType == 'WFH' else 'ABSENT',
                    requestId=request_approval.id  # Track which request created this
                )
                db.session.add(attendance)

        # Handle rejection with cleanup
        elif new_status == 'REJECTED' and request_approval.requestStatus == 'APPROVED':
            # Delete only attendance records created by this request
            Attendance.query.filter(
                Attendance.requestId == request_approval.id
            ).delete()

        # Update request status
        request_approval.requestStatus = new_status
        db.session.commit()

        return jsonify({"message": "Request status updated successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 400


# Comprehensive API to get requests with various filters
@app.route('/request-approvals', methods=['POST'])
@admin_required
def get_requests():
    try:
        # Get all possible filter parameters
        request_id = request.args.get('id')
        requester_emp_id = request.args.get('requesterEmpId')
        approver_emp_id = request.args.get('approverEmpId')
        request_type = request.args.get('requestType')
        request_status = request.args.get('requestStatus')
        from_date = request.args.get('fromDate')
        to_date = request.args.get('toDate')

        # Start with base query
        query = RequestApproval.query

        # Apply filters if they exist
        if request_id:
            query = query.filter(RequestApproval.id == request_id)
        if requester_emp_id:
            query = query.filter(RequestApproval.requesterEmpId == requester_emp_id)
        if approver_emp_id:
            query = query.filter(RequestApproval.approverEmpId == approver_emp_id)
        if request_type:
            query = query.filter(RequestApproval.requestType == request_type.upper())
        if request_status:
            query = query.filter(RequestApproval.requestStatus == request_status.upper())
        if from_date:
            from_date_obj = datetime.strptime(from_date, "%Y-%m-%d").date()
            query = query.filter(RequestApproval.fromDate >= from_date_obj)
        if to_date:
            to_date_obj = datetime.strptime(to_date, "%Y-%m-%d").date()
            query = query.filter(RequestApproval.toDate <= to_date_obj)

        # Execute query
        requests = query.all()

        # Format response
        response = [{
            "id": req.id,
            "requesterEmpId": req.requesterEmpId,
            "approverEmpId": req.approverEmpId,
            "requestType": req.requestType,
            "requestStatus": req.requestStatus,
            "requestCreatedDate": req.requestCreatedDate.strftime("%Y-%m-%d"),
            "fromDate": req.fromDate.strftime("%Y-%m-%d"),
            "toDate": req.toDate.strftime("%Y-%m-%d")
        } for req in requests]

        return jsonify(response), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# API to get requests for specific user (based on their role)
@app.route('/employees/<int:emp_id>/requests', methods=['POST'])
@admin_required
def get_employee_requests(emp_id):
    try:
        # Check if user wants requests they created or requests they need to approve
        request_type = request.args.get('type', 'all')  # 'created', 'approval', or 'all'

        base_query = RequestApproval.query

        if request_type == 'created':
            requests = base_query.filter(RequestApproval.requesterEmpId == emp_id).all()
        elif request_type == 'approval':
            requests = base_query.filter(RequestApproval.approverEmpId == emp_id).all()
        else:
            requests = base_query.filter(
                (RequestApproval.requesterEmpId == emp_id) |
                (RequestApproval.approverEmpId == emp_id)
            ).all()

        response = [{
            "id": req.id,
            "requesterEmpId": req.requesterEmpId,
            "approverEmpId": req.approverEmpId,
            "requestType": req.requestType,
            "requestStatus": req.requestStatus,
            "requestCreatedDate": req.requestCreatedDate.strftime("%Y-%m-%d"),
            "fromDate": req.fromDate.strftime("%Y-%m-%d"),
            "toDate": req.toDate.strftime("%Y-%m-%d"),
            "isRequester": req.requesterEmpId == emp_id,
            "isApprover": req.approverEmpId == emp_id
        } for req in requests]

        return jsonify(response), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# API to delete a request in PENDING state
@app.route('/request-approvals/<int:request_id>', methods=['DELETE'])
@admin_required
def delete_pending_request(request_id):
    try:
        # Get the request
        request_approval = RequestApproval.query.get(request_id)
        if not request_approval:
            return jsonify({"error": "Request not found"}), 404

        # Check if request is in PENDING state or not
        if request_approval.requestStatus != "PENDING":
            return jsonify({
                "error": "Cannot delete request",
                "message": "Only requests in PENDING state can be deleted",
                "currentStatus": request_approval.requestStatus
            }), 400

        # Check if current user is the requester or an admin
        current_user_id = int(get_jwt_identity())
        if current_user_id != request_approval.requesterEmpId:
            # Verify if user is admin (level 7-9) or the approver
            current_user = Employee.query.get(current_user_id)
            if not current_user or current_user.level < 7:
                if current_user_id != request_approval.approverEmpId:
                    return jsonify({
                        "error": "Unauthorized",
                        "message": "Only requester, approver or admin can delete requests"
                    }), 403

        # Delete the request
        db.session.delete(request_approval)
        db.session.commit()

        return jsonify({
            "message": "Request deleted successfully",
            "deletedRequestId": request_id
        }), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    app.run(port=5003, debug=True)