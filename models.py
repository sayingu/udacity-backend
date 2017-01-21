from google.appengine.ext import db


def user_key(group="default"):
    return db.Key.from_path("users", group)


class User(db.Model):

    """Kind User"""
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def _get_by_id(cls, user_id):
        return cls.get_by_id(int(user_id), parent=user_key())

    @classmethod
    def _get_by_username(cls, username):
        return cls.all().filter('username =', username).get()


def post_key(param="default"):
    return db.Key.from_path("posts", param)


class Post(db.Model):

    """Kind Post (store blog posts)"""
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    username = db.StringProperty(required=True)
    like = db.IntegerProperty(default=0)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def _get_all(cls):
        return cls.all().ancestor(post_key()).order("-created").fetch(limit=10)

    @classmethod
    def _get_by_id(cls, post_id):
        return cls.get_by_id(int(post_id), parent=post_key())

    @classmethod
    def _get_like(cls, post_id, username):
        """method that get post's liked data"""
        return Post_Like._get(post_id, username)

    @classmethod
    def _get_comments(cls, post_id):
        """method that get post's comments data"""
        return Post_Comment._get_all_by_post_id(post_id)


def post_like_key(param="default"):
    return db.Key.from_path("post_likes", param)


class Post_Like(db.Model):

    """Kind Post_Like (store username per post)"""
    post_id = db.IntegerProperty(required=True)
    username = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def _get(cls, post_id, username):
        query = cls.all().ancestor(post_like_key())
        query = query.filter("post_id =", int(post_id))
        query = query.filter("username =", username)
        return query.get()


def post_comment_key(param="default"):
    return db.Key.from_path("post_comments", param)


class Post_Comment(db.Model):

    """Kind Post_Comment (store post's comment)"""
    post_id = db.IntegerProperty(required=True)
    content = db.TextProperty(required=True)
    username = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def _get_all_by_post_id(cls, post_id):
        query = cls.all().ancestor(post_comment_key())
        query = query.filter("post_id =", int(post_id))
        return query.order("-created")

    @classmethod
    def _get_by_id(cls, comment_id):
        return cls.get_by_id(int(comment_id), parent=post_comment_key())
