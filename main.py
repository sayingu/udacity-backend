#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.`
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import logging
import webapp2
import re
import hmac
import random
from string import letters
import hashlib
import time

import jinja2

import models

template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir), autoescape=True)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


class Handler(webapp2.RequestHandler):

    """
    Handler : request handler
        if cookies have correct user_id then throws user param
    """

    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        if self.user:
            params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)

        user_id_hashed = self.request.cookies.get("user_id")
        user_id = check_secure_val(user_id_hashed)

        self.user = user_id is not None and models.User._get_by_id(user_id)


# BLOG STUFF


class BlogHandler(Handler):

    """mapping for url ('/', /blog')"""

    def get(self):
        self.render("blog_posts.html", posts=models.Post._get_all())


class NewpostHandler(Handler):

    """mapping for url ('/blog/newpost')"""

    def get(self):
        # user exist check
        user = self.user
        if not user:
            self.redirect("/login")
            return

        self.render("blog_editpost.html")

    def post(self):
        # user exist check
        user = self.user
        if not user:
            self.redirect("/login")
            return

        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            post = models.Post(parent=models.post_key(),
                               subject=subject,
                               content=content,
                               username=self.user.username)
            post.put()

            self.redirect("/blog#%s" % str(post.key().id()))
        else:
            error_msg = "we need both a subject and some blog!"
            self.render("blog_editpost.html", subject=subject,
                        content=content,
                        error_msg=error_msg)


class PostHandler(Handler):

    """mapping for url ('/blog/([0-9]+)')"""

    def get(self, post_id):
        # post exist check
        post = models.Post._get_by_id(post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        self.render("blog_post.html", post=post)


class PostEditHandler(Handler):

    """mapping for url ('/blog/([0-9]+)/edit')"""

    def get(self, post_id):
        # post exist check
        post = models.Post._get_by_id(post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        # user exist, authorization check
        user = self.user
        if not user or user.username != post.username:
            self.redirect("/login")
            return

        self.render("blog_editpost.html", post_id=post_id,
                    subject=post.subject,
                    content=post.content)

    def post(self, post_id):
        # post exist check
        post = models.Post._get_by_id(post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        # user exist, authorization check
        user = self.user
        if not user or user.username != post.username:
            self.redirect("/login")
            return

        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            post = models.Post._get_by_id(post_id)

            post.subject = subject
            post.content = content

            post.put()

            self.redirect("/blog#%s" % post_id)
        else:
            error_msg = "we need both a subject and some blog!"
            self.render("blog_editpost.html", subject=subject,
                        content=content,
                        error_msg=error_msg)


class PostDeleteHandler(Handler):

    """mapping for url ('/blog/([0-9]+)/delete')"""

    def get(self, post_id):
        # post exist check
        post = models.Post._get_by_id(post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        # user exist, authorization check
        user = self.user
        if not user or user.username != post.username:
            self.redirect("/login")
            return

        post.delete()

        self.redirect("/blog")


class PostLikeHandler(Handler):

    """mapping for url ('/blog/([0-9]+)/like')"""

    def get(self, post_id):
        # post exist check
        post = models.Post._get_by_id(post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        # user exist check
        user = self.user
        if not user:
            self.redirect("/login")
            return

        if post.username != user.username:
            post_like = models.Post_Like._get(post_id, user.username)

            if not post_like:
                # if post liked data is not exist, then like has increase by 1
                # and put data to Post_Like Kind
                post.like += 1
                post.put()

                post_like = models.Post_Like(
                    parent=models.post_like_key(),
                    post_id=int(post_id),
                    username=self.user.username)

                post_like.put()
            else:
                # if post liked data is exist, then like has decrease by 1 and
                # delet data to Post_Like Kind
                post.like -= 1
                post.put()

                post_like.delete()

        self.redirect("/blog#%s" % post_id)


class NewcommentHandler(Handler):

    """mapping for url ('/blog/([0-9]+)/newcomment')"""

    def get(self, post_id):
        # post exist check
        post = models.Post._get_by_id(post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        # user exist check
        user = self.user
        if not user:
            self.redirect("/login")
            return

        self.render("blog_editcomment.html", post_id=post_id)

    def post(self, post_id):
        # post exist check
        post = models.Post._get_by_id(post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        # user exist check
        user = self.user
        if not user:
            self.redirect("/login")
            return

        content = self.request.get("content")

        if content:
            post_comment = models.Post_Comment(
                parent=models.post_comment_key(),
                post_id=int(post_id),
                content=content,
                username=self.user.username)
            post_comment.put()

            self.redirect("/blog#%s" % post_id)
        else:
            error_msg = "we need some comment!"
            self.render(
                "blog_editcomment.html", content=content, error_msg=error_msg)


class CommentEditHandler(Handler):

    """mapping for url ('/blog/([0-9]+)/([0-9]+)/edit')"""

    def get(self, post_id, comment_id):
        # post exist check
        post = models.Post._get_by_id(post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        # comment exist check
        post_comment = models.Post_Comment._get_by_id(comment_id)
        if not post_comment:
            self.error(404)
            self.render("404.html")
            return

        # user exist, authorization check
        user = self.user
        if not user or user.username != post_comment.username:
            self.redirect("/login")
            return

        self.render("blog_editcomment.html", post_id=post_id,
                    comment_id=comment_id,
                    content=post_comment.content)

    def post(self, post_id, comment_id):
        # post exist check
        post = models.Post._get_by_id(post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        # comment exist check
        post_comment = models.Post_Comment._get_by_id(comment_id)
        if not post_comment:
            self.error(404)
            self.render("404.html")
            return

        # user exist, authorization check
        user = self.user
        if not user or user.username != post_comment.username:
            self.redirect("/login")
            return

        content = self.request.get("content")

        if content:
            post_comment = models.Post_Comment._get_by_id(comment_id)

            post_comment.content = content

            post_comment.put()

            self.redirect("/blog#%s" % post_id)
        else:
            error_msg = "we need both a subject and some blog!"
            self.render(
                "blog_editcomment.html", content=content, error_msg=error_msg)


class CommentDeleteHandler(Handler):

    """mapping for url ('/blog/([0-9]+)/([0-9]+)/delete')"""

    def get(self, post_id, comment_id):
        # post exist check
        post = models.Post._get_by_id(post_id)
        if not post:
            self.error(404)
            self.render("404.html")
            return

        # comment exist check
        post_comment = models.Post_Comment._get_by_id(comment_id)
        if not post_comment:
            self.error(404)
            self.render("404.html")
            return

        # user exist, authorization check
        user = self.user
        if not user or user.username != post_comment.username:
            self.redirect("/login")
            return

        post_comment.delete()

        self.redirect("/blog#%s" % post_id)

# SIGNUP STUFF
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")


def valid_email(email):
    return EMAIL_RE.match(email) if email else True

SECRET = "UDACITY"


def make_secure_val(s):
    """make hash data using hmac"""
    return "%s|%s" % (s, hmac.new(SECRET, s).hexdigest())


def check_secure_val(h):
    """check hash data using hmac"""
    if h:
        val = h.split('|')[0]
        if h == make_secure_val(val):
            return val


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


class SignupHandler(Handler):

    """mapping for url ('/signup')"""

    def get(self):
        self.render("signup.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        username_error_msg = ""
        password_error_msg = ""
        verify_error_msg = ""
        email_error_msg = ""

        user = models.User._get_by_username(username)

        valid = True
        if not valid_username(username):
            username_error_msg = "That's not a valid username."
            valid = False

        if user is not None:
            username_error_msg = "That user already exists."
            valid = False

        if not valid_password(password):
            password_error_msg = "That wasn't a valid password."
            valid = False

        if password != verify:
            verify_error_msg = "Your passwords didn't match."
            valid = False

        if not valid_email(email):
            email_error_msg = "That's not a valid email."
            valid = False

        if valid:
            user = models.User(parent=models.user_key(),
                               username=username,
                               password=make_pw_hash(username, password),
                               email=email)
            user.put()

            self.response.headers.add_header(
                "Set-Cookie",
                "user_id=%s; Path=/"
                % str(make_secure_val(str(user.key().id()))))

            self.redirect("/welcome")
        else:
            self.render("signup.html", username=username,
                        email=email,
                        username_error_msg=username_error_msg,
                        password_error_msg=password_error_msg,
                        verify_error_msg=verify_error_msg,
                        email_error_msg=email_error_msg)


class LoginHandler(Handler):

    """mapping for url ('/login')"""

    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")

        login_error_msg = "Invalid login"

        user = models.User._get_by_username(username)

        valid = False
        if user and valid_pw(username, password, user.password):
            valid = True

        if valid:
            rememberme = self.request.get("remember-me")
            expires_str = ""

            if rememberme and rememberme == "remember-me":
                expires = time.time() + 30 * 24 * 3600  # 30 days from now
                expires_str = time.strftime(
                    "%a, %d-%b-%Y %H:%M:%S GMT", time.gmtime(expires))

            self.response.headers.add_header(
                "Set-Cookie",
                "user_id=%s; expires=%s; Path=/"
                % (str(make_secure_val(str(user.key().id()))), expires_str))

            self.redirect("/welcome")
        else:
            self.render("login.html", login_error_msg=login_error_msg)


class LogoutHandler(Handler):

    """mapping for url ('/logout')"""

    def get(self):
        # user exist check
        user = self.user
        if not user:
            self.redirect("/login")
            return

        self.response.headers.add_header("Set-Cookie", "user_id=; Path=/")

        self.redirect("/blog")


class WelcomeHandler(Handler):

    """mapping for url ('/welcome')"""

    def get(self):
        # user exist check
        user = self.user
        if not user:
            self.redirect("/login")
            return

        self.render("welcome.html", username=user.username)

app = webapp2.WSGIApplication([
    ('/', BlogHandler),
    ('/blog', BlogHandler),
    ('/blog/newpost', NewpostHandler),
    ('/blog/([0-9]+)', PostHandler),
    ('/blog/([0-9]+)/delete', PostDeleteHandler),
    ('/blog/([0-9]+)/edit', PostEditHandler),
    ('/blog/([0-9]+)/like', PostLikeHandler),
    ('/blog/([0-9]+)/newcomment', NewcommentHandler),
    ('/blog/([0-9]+)/([0-9]+)/edit', CommentEditHandler),
    ('/blog/([0-9]+)/([0-9]+)/delete', CommentDeleteHandler),
    ('/signup', SignupHandler),
    ('/welcome', WelcomeHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler)
], debug=True)
