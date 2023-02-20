import os
from unittest import TestCase
import app

from datetime import date
 
from books_app.extensions import app, db, bcrypt
from books_app.models import Book, Author, User, Audience

"""
Run these tests with the command:
python -m unittest books_app.main.tests
"""

#################################################
# Setup
#################################################

def create_books():
    a1 = Author(name='Harper Lee')
    b1 = Book(
        title='To Kill a Mockingbird',
        publish_date=date(1960, 7, 11),
        author=a1
    )
    db.session.add(b1)

    a2 = Author(name='Sylvia Plath')
    b2 = Book(title='The Bell Jar', author=a2)
    db.session.add(b2)
    db.session.commit()

def create_user():
    password_hash = bcrypt.generate_password_hash('password').decode('utf-8')
    user = User(username='me1', password=password_hash)
    db.session.add(user)
    db.session.commit()

def create_author():
    a1 = Author(
            name='Dan Brown',
            biography="Daniel Gerhard Brown is an American author best known for his thriller novels, including the Robert Langdon novels."
        )
    db.session.add(a1)

    a2 = Author(
        name='Nora Roberts',
        biography="Nora Roberts is an American author of more than 225 romance novels.")
    db.session.add(a2)
    db.session.commit()


def login(client, username, password):
    return client.post('/login', data=dict(
        username=username,
        password=password
    ), follow_redirects=True)

def logout(client):
    return client.get('/logout', follow_redirects=True)

#################################################
# Tests
#################################################

class AuthTests(TestCase):
    """Tests for authentication (login & signup)."""
 
    def setUp(self):
        """Executed prior to each test."""
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['DEBUG'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        db.drop_all()
        db.create_all()

    def test_signup(self):
        # TODO: Write a test for the signup route. It should:
        # - Make a POST request to /signup, sending a username & password
        post_data = {
            "username": "Vitavita",
            "password": "passpass"
        }
        self.app.post('/signup', data=post_data, follow_redirects=True)
        # - Check that the user now exists in the database
        created_user = User.query.filter_by(username="Vitavita").one()
        self.assertIsNotNone(created_user)
        self.assertEqual(created_user.username, "Vitavita")

    def test_signup_existing_user(self):
        # TODO: Write a test for the signup route. It should:
        # - Create a user
        create_user()
        # - Make a POST request to /signup, sending the same username & password
        post_data = {
            'username': 'me1',
            'password': 'password'
        }
        self.app.post('/signup', data=post_data, follow_redirects=True)
        # - Check that the form is displayed again with an error message
        response = self.app.post('/signup', data=post_data)
        response_text = response.get_data(as_text=True)
        self.assertIn('That username is taken. Please choose a different one.', response_text)

    def test_login_correct_password(self):
        # TODO: Write a test for the login route. It should:
        # - Create a user
        create_user()
        # - Make a POST request to /login, sending the created username & password
        post_data = {
            'username': 'me1',
            'password': 'password'
        }
        response = self.app.post('/login', data=post_data, follow_redirects = True)
        response_text = response.get_data(as_text=True)
        # - Check that the "login" button is not displayed on the homepage
        self.assertNotIn('Log In', response_text)

    def test_login_nonexistent_user(self):
        # TODO: Write a test for the login route. It should:
        # - Make a POST request to /login, sending a username & password
        post_data = {
            'username': 'randononex',
            'password': 'password'
        }
        response = self.app.post('/login', data=post_data, follow_redirects = True)
        response_text = response.get_data(as_text=True)
        # - Check that the login form is displayed again, with an appropriate
        #   error message
        self.assertIn("No user with that username. Please try again.", response_text)
        

    def test_login_incorrect_password(self):
        # TODO: Write a test for the login route. It should:
        # - Create a user
        create_user()
        # - Make a POST request to /login, sending the created username &
        #   an incorrect password
        post_data = {
            'username': 'me1',
            'password': 'nonexpass'
        }
        response = self.app.post('/login', data=post_data, follow_redirects = True)
        response_text = response.get_data(as_text=True)
        # - Check that the login form is displayed again, with an appropriate
        #   error message
        self.assertIn("Password does not match. Please try again.", response_text)

    def test_logout(self):
        # TODO: Write a test for the logout route. It should:
        # - Create a user
        create_user()
        # - Log the user in (make a POST request to /login)
        post_data = {
            'username': 'me1',
            'password': 'nonexpass'
        }
        self.app.post('/login', data=post_data, follow_redirects = True)
        # - Make a GET request to /logout
        response = self.app.get('/logout', follow_redirects=True)
        response_text = response.get_data(as_text=True)
        # - Check that the "login" button appears on the homepage
        self.assertIn('Log In', response_text)
