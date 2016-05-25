from google.appengine.ext import ndb

class Comentario(ndb.Model):
    titulo = ndb.StringProperty(required=True)
    autor = ndb.StringProperty()
    texto = ndb.TextProperty(required=True)
    verificado = ndb.StringProperty(required=True)
    fecha_creacion = ndb.DateProperty()

class Usuario(ndb.Model):
    correo = ndb.StringProperty (required=True)
    nombre = ndb.StringProperty ()
    passwd = ndb.StringProperty (required=True)
    tipoUsuario = ndb.StringProperty (required=True)
