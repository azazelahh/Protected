from flask import Flask, request, Response, render_template
from functools import wraps


app = Flask(__name__)

USERNAME = 'admin'
PASSWORD = 'letmein'
ip_failed_attempts = {}


def increment_failed_login_count(ip):
    """Increments failed login count for user ip."""

    if ip not in ip_failed_attempts:
        ip_failed_attempts[ip] = 0
    ip_failed_attempts[ip] += 1


def check_auth(username, password):
    """Checks if a username / password combination is valid."""
    return username == USERNAME and password == PASSWORD


def authenticate(ip):
    """Checks if user exceeded failed attempt limit. If not,
    prompts user to authenticate by sending a 401 response that enables basic auth.
    """
    increment_failed_login_count(ip)
    if ip_failed_attempts[ip] > 3:
        return render_template('login_fail.html')
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'})


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate(request.environ['REMOTE_ADDR'])
        return f(*args, **kwargs)
    return decorated


@app.route('/')
@requires_auth
def page1():
    return render_template('page1.html')


@app.route('/page2')
@requires_auth
def page2():
    return render_template('page2.html')



if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')

