import os
import verification
import webapp2
import jinja2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

class User(db.Model):
    username=db.StringProperty(required = True)
    password=db.StringProperty(required = True)
    email=db.StringProperty(required = False)
    joined=db.DateTimeProperty(auto_now_add = True)

class Post(db.Model):
    title= db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    
    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return jinja_env.get_template("post.html").render(p = self)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        cookie = self.request.cookies.get('username')
        if cookie and verification.verify_cookie(cookie):
            uid = cookie.split('|')[0]
            uk = db.Key.from_path("User", int(uid))
            params['user'] = db.get(uk)
            
        return t.render(params)
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class Main(Handler):
    def render_front(self, title="", content="", error=""):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC LIMIT 10")
        self.render("main.html", posts=posts)
    def get(self):
        self.render_front()
    
    
class New(Handler):
    def render_front(self, title="", content="", error=""):
        self.render("newpost.html", title=title, content=content, error=error)    
    def get(self):
        cookie = self.request.cookies.get('username')
        if cookie and verification.verify_cookie(cookie):
            self.render_front()
        else:
            self.redirect('/signup')
    def post(self):
        title = self.request.get("subject")
        content = self.request.get("content")
        
        if title and content:
            a = Post(title = title, content=content)
            a.put()
            self.redirect("/%s" % str(a.key().id()))
        else:
            self.render_front(title=title, content=content, error="We need a title AND content!")

class Perma(Handler):
    def get(self, pid):
        k = db.Key.from_path("Post", int(pid))
        post = db.get(k)
        if not post:
            self.error(404)
            return
        self.render("permalink.html", post=post)
        
            
class SignUp(Handler):
    def render_front(self, **errors):
        self.render("signup.html", **errors)
    def get(self):
        self.render_front()
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        
        params = {'username':username,'email':email}
        is_error = False
     
        q = db.GqlQuery("select * from User where username = :1", username).get()
        
        if not verification.valid_username(username):
            params['usernameerror']='Not A Valid Username'
            is_error = True
        elif q:
            params['usernameerror']='Username already taken'
            is_error = True            
        if not verification.valid_password(password):
            params['passworderror']='Not A Valid Password'
            is_error = True
        elif password != verify:
            params['verifyerror']='Passwords do not match'
            is_error = True
        if not verification.valid_email(email):
            params['emailerror']='Invalid Email'
            is_error = True
            
        if is_error:
            self.render_front(**params)
        else:
            a = User(username=username, password=verification.make_pw_hash(username,password), email=email)
            a.put()
            self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % verification.make_cookie(str(a.key().id())))
            self.redirect("/")
            

        
class Login(Handler):
    def render_front(self, **errors):
        self.render("login.html", **errors)
    def get(self):
        self.render_front()
    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        
        params={'username':username}
        is_error=False
        q = db.GqlQuery("select * from User where username = :1", username).get()
        
        if q and verification.valid_pw(username, password, q.password):
            self.response.headers.add_header('Set-Cookie', 'username=%s; Path=/' % verification.make_cookie(str(q.key().id())))
            self.redirect('/')
            
        else:
            params['error']='Login Error'
            self.render_front(**params)
            
class Logout(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie','username=; Path=/')
        self.redirect('/signup')
            
app = webapp2.WSGIApplication(
    [('/', Main), 
     ('/newpost', New),
     ('/([0-9]+)', Perma),
     ('/signup', SignUp),
     ('/login', Login),
     ('/logout', Logout)],
    debug=True)
