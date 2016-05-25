#!/usr/bin/env python
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
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import urllib
import datetime
import re
import base64

from google.appengine.api import users
from google.appengine.ext import ndb

import webapp2
import jinja2
from models import *

JINJA_ENVIRONMENT = jinja2.Environment(
                                       loader=jinja2.FileSystemLoader(os.path.dirname(__file__)),
                                       extensions=['jinja2.ext.autoescape'],
                                       autoescape=True)
NOMBRE = ""
CORREO = ""
TIPO_USUARIO = ""
TITULO = ""
AUTOR = ""


######### ANONIMO ############

class Inicio(webapp2.RequestHandler):
    
    def get(self):
        Comentarios = Comentario.query(Comentario.verificado == 'SI')
        Comentarios.fetch(limit = 15)
        template_values = {'Comentarios' : Comentarios}
        template = JINJA_ENVIRONMENT.get_template('views/inicio.html')
        self.response.write(template.render(template_values))

class IniciarSesion(webapp2.RequestHandler):
    
    def get(self):
        template_values = {}
        template = JINJA_ENVIRONMENT.get_template('views/iniciarSesion.html')
        self.response.write(template.render(template_values))

    def post(self):
        
        contr = self.request.get('passwd')
        email = self.request.get('email')
        q = Usuario.query(Usuario.correo == email)
        us = q.get()
        passDecodificada = base64.decodestring(us.passwd)
        error = False
        if us is None:
           error = True
        elif passDecodificada != contr:
           error = True
        
        if error == True:
            template_values = {
                'mensaje_error' : "Incorrecto",
                'email' : email
            }
            template = JINJA_ENVIRONMENT.get_template('views/iniciarSesion.html')
            self.response.write(template.render(template_values))
        else:
            global TIPO_USUARIO
            TIPO_USUARIO = us.tipoUsuario
            global CORREO
            CORREO = email
            global NOMBRE
            NOMBRE = us.nombre
            if TIPO_USUARIO == 'admin':
                self.redirect('/inicioAdmin')
            else:
                self.redirect('/inicioUsuario')


class Registro(webapp2.RequestHandler):

    def get(self):
        id = self.request.get('id')
                                    
        template_values = {}
        template = JINJA_ENVIRONMENT.get_template('views/registro.html')
        self.response.write(template.render(template_values))
    
    def post(self):
        validar_error = ""
        email_error = ""
        passwd_error = ""
        
        PASSWORD_RE = re.compile(r"^.{3,20}$")
        EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
        
        def valid_password(passwd):
            return PASSWORD_RE.match(passwd)
        
        def valid_email(correo):
            return EMAIL_RE.match(correo)
        
        contr1 = self.request.get('passwd1')
        contr2 = self.request.get('passwd2')
        correo= self.request.get('email')
        nombre=self.request.get('nombre')
        
        
        q = Usuario.query(Usuario.correo == correo)
        us = q.get()

        error = False
        if us is not None:
            email_error = "El usuario ya existe"
        if not valid_email(correo):
            email_error = "Incorrecto"
            error = True
        if correo is None:
            email_error = "Campo requerido"
            error = True
        if not valid_password(contr1):
            passwd_error = "Incorrecto"
            error = True
        if contr1 is None:
            passwd_error = "Campo requerido"
            error = True
        if contr1 != contr2:
            validar_error = "No coinciden"
            error = True
        if error:
            template_values = {
                'email' : correo,
                'nombre' : nombre,
                'validar_error' : validar_error,
                'email_error' : email_error,
                'passwd_error' : passwd_error,
            }
            template = JINJA_ENVIRONMENT.get_template('views/registro.html')
            self.response.write(template.render(template_values))
        else:
            contr1 = base64.encodestring(contr1)
            self.usuario = Usuario(correo = correo,
                                   nombre = nombre,
                                   passwd = contr1,
                                   tipoUsuario = 'usr',
                                   )
            self.usuario.put()
            self.redirect('/')

class comentarios(webapp2.RequestHandler):

    def get(self):
        q = Comentario.query(Comentario.verificado == 'SI')
        q.order(Comentario.autor).fetch()
        template_values = {'Comentarios' : q}
        template = JINJA_ENVIRONMENT.get_template('views/comentarios.html')
        self.response.write(template.render(template_values))

    def post(self):
        q = Comentario.query(Comentario.verificado == 'SI')
        q = q.filter(Comentario.autor == self.request.get('autor'))
        template_values = {'Comentarios' : q}
        template = JINJA_ENVIRONMENT.get_template('views/comentarios.html')
        self.response.write(template.render(template_values))


########### USUARIO  ##############

class InicioUsuario(webapp2.RequestHandler):
    
    def get(self):
        global TIPO_USUARIO
        if TIPO_USUARIO != 'usr':
            self.redirect('/')
        Comentarios = Comentario.query(Comentario.verificado == 'SI')
        lista_Comentarios = Comentarios.fetch(limit=15)
        template_values = {'Comentarios' : lista_Comentarios}
        template = JINJA_ENVIRONMENT.get_template('views/inicioUsuario.html')
        self.response.write(template.render(template_values))

class Publicar(webapp2.RequestHandler):
    
    def get(self):
        global TIPO_USUARIO
        if TIPO_USUARIO != 'usr':
            self.redirect('/')
        template_values = {}
        template = JINJA_ENVIRONMENT.get_template('views/publicar.html')
        self.response.write(template.render(template_values))
    
    def post(self):
        global NOMBRE
        Comentarios = Comentario(titulo = self.request.get('titulo'),
                        texto = self.request.get('texto'),
                        autor = NOMBRE,
                        fecha_creacion = datetime.datetime.now().date(),
                        verificado = 'NO',
                        )
        
        Comentarios.put()
        self.redirect('/inicioUsuario')

class Perfil (webapp2.RequestHandler):

    def get(self):
        if TIPO_USUARIO != 'usr':
            self.redirect('/')
        global CORREO
        global NOMBRE
        q = Usuario.query(Usuario.correo == CORREO)
        us = q.get()
        NOMBRE = us.nombre
        Comentarios = Comentario.query(Comentario.autor == us.nombre)
        Comentarios.fetch()
        numComentarios = Comentarios.count()
        
        template_values = {
                            'nombre' : us.nombre,
                            'email' : us.correo,
                            'numComentarios' : numComentarios,
                            'Comentarios' : Comentarios,}
        template = JINJA_ENVIRONMENT.get_template('views/perfil.html')
        self.response.write(template.render(template_values))

class comentariosUsuario(webapp2.RequestHandler):

    def get(self):
        q = Comentario.query(Comentario.verificado == 'SI')
        q.order(Comentario.autor).fetch()
        template_values = {'Comentarios' : q}
        template = JINJA_ENVIRONMENT.get_template('views/comentariosUsuario.html')
        self.response.write(template.render(template_values))
    
    def post(self):
        q = Comentario.query(Comentario.verificado == 'SI')
        q = q.filter(Comentario.autor == self.request.get('autor'))
        template_values = {'Comentarios' : q}
        template = JINJA_ENVIRONMENT.get_template('views/comentariosUsuario.html')
        self.response.write(template.render(template_values))

########### ADMIN  ##############

class InicioAdmin(webapp2.RequestHandler):
    
    def get(self):
        global TIPO_USUARIO
        if TIPO_USUARIO != 'admin':
            self.redirect('/')
        q = Comentario.query(Comentario.verificado == 'SI')
        q.order(Comentario.fecha_creacion)
        template_values = {'Comentarios' : q}
        template = JINJA_ENVIRONMENT.get_template('views/inicioAdmin.html')
        self.response.write(template.render(template_values))

class Administrar(webapp2.RequestHandler):
    
    def get(self):
        global TIPO_USUARIO
        if TIPO_USUARIO != 'admin':
            self.redirect('/')
        q = Comentario.query(Comentario.verificado == 'NO')
        Comentarios = q.get()
        template_values = {'Comentarios' : q}
        template = JINJA_ENVIRONMENT.get_template('views/administrar.html')
        self.response.write(template.render(template_values))


class AceptarComentario (webapp2.RequestHandler):

    def get(self):
        global TITULO
        global AUTOR
        global TIPO_USUARIO
        if TIPO_USUARIO != 'usr':
            self.redirect('/')
        autor = AUTOR
        titulo = TITULO

        Comentario_Aceptar = Comentario.query(Comentario.titulo == titulo)
        Comentario_Aceptar.filter(Comentario.autor == autor)
        Comentarios = Comentario_Aceptar.get()
        Comentarios.verificado = 'SI'
        #Comentarios = Comentario_Aceptar.put()
        Comentarios.put()

        
        #volver a cargar la pagina de InicioAdmin
        Comentarios = Comentario.query(Comentario.verificado == 'NO')
        lista_Comentarios = Comentarios.fetch()
        template_values = {}
        template = JINJA_ENVIRONMENT.get_template('views/administrar.html')
        self.response.write(template.render(template_values))


class RechazarComentario (webapp2.RequestHandler):

    def get(self):
        global TIPO_USUARIO
        if TIPO_USUARIO != 'usr':
            self.redirect('/')
        global TITULO
        global AUTOR
        global TIPO_USUARIO
        if TIPO_USUARIO != 'usr':
            self.redirect('/')
        autor = AUTOR
        titulo = TITULO
        Comentario_Rechazar = Comentario.query(Comentario.titulo == titulo)
        Comentario_Rechazar.filter(Comentario.autor == autor)
        Comentarios = Comentario_Rechazar.get()
        Comentarios.key.delete()
        
        #volver a cargar la pagina de InicioAdmin
        Comentarios = Comentario.query(Comentario.verificado == 'NO')
        lista_Comentarios = Comentarios.fetch()
        template_values = {}
        template = JINJA_ENVIRONMENT.get_template('views/administrar.html')
        self.response.write(template.render(template_values))

class comentariosAdmin(webapp2.RequestHandler):

    def get(self):
        q = Comentario.query(Comentario.verificado == 'SI')
        q.order(Comentario.autor).fetch()
        template_values = {'Comentarios' : q}
        template = JINJA_ENVIRONMENT.get_template('views/comentariosAdmin.html')
        self.response.write(template.render(template_values))
    
    def post(self):
        q = Comentario.query(Comentario.verificado == 'SI')
        q = q.filter(Comentario.autor == self.request.get('autor'))
        template_values = {'Comentarios' : q}
        template = JINJA_ENVIRONMENT.get_template('views/comentariosAdmin.html')
        self.response.write(template.render(template_values))

class CerrarSesion (webapp2.RequestHandler):

    def get(self):
        global NOMBRE
        NOMBRE = ""
        global CORREO
        CORREO = ""
        self.redirect('/')

app = webapp2.WSGIApplication([
    ('/', Inicio),
    ('/inicioUsuario', InicioUsuario),
    ('/inicioAdmin', InicioAdmin),
    ('/iniciarSesion', IniciarSesion),
    ('/registro', Registro),
    ('/cerrarSesion' , CerrarSesion),
    ('/perfil' , Perfil),
    ('/publicar', Publicar),
    ('/comentarios' , comentarios),
    ('/comentariosAdmin' , comentariosAdmin),
    ('/comentariosUsuario' , comentariosUsuario),
    ('/administrar' , Administrar),
    ('/rechazarComentario' , RechazarComentario),
    ('/aceptarComentario' , AceptarComentario)
], debug=True)
