from flask_jwt_extended import JWTManager
from flask_jwt_extended import jwt_required
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import create_access_token, verify_jwt_in_request
from flask import Flask
from flask import jsonify
from flask import request
from flask_cors import CORS
import json
from waitress import serve
import datetime
import requests
import re

app = Flask(__name__)
cors = CORS(app)

app.config["JWT_SECRET_KEY"] = "code-dev"
jwt = JWTManager(app)


############################
# Implementación del Login #
############################

@app.route("/login", methods=["POST"])
def create_token():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + '/usuarios/validar'
    response = requests.post(url,  headers=headers, json=data)

    if response.status_code == 200:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60 * 24)
        access_token = create_access_token(
            identity=user, expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        return jsonify({"msg": "Error en usuario o contrasena"}), 401


####################################
# Implementación Creación de usuario
####################################

@app.route("/singup", methods=["POST"])
def create_user():
    data = request.get_json()
    headers = {"Content-Type": "application/json; charset=utf-8"}
    url = dataConfig["url-backend-seguridad"] + '/usuarios'
    response = requests.post(url, headers=headers, json=data)

    if response.status_code == 201:
        user = response.json()
        expires = datetime.timedelta(seconds=60 * 60 * 24)
        access_token = create_access_token(
            identity=user, expires_delta=expires)
        return jsonify({"token": access_token, "user_id": user["_id"]})
    else:
        return jsonify({"msg": "Error en la creación del usuario"}), 400


##############
# Middleware #
##############

@ app.before_request
def before_request_callback():
    endPoint=limpiarURL(request.path)
    excludedRoutes=["/login", "/singup"]

    if excludedRoutes.__contains__(request.path):
        print("ruta excluida ", request.path)
        pass

    elif verify_jwt_in_request():
        usuario=get_jwt_identity()

        if usuario["rol"] is not None:
            tienePersmiso=validarPermiso(
                endPoint, request.method, usuario["rol"]["_id"])

            if not tienePersmiso:
                return jsonify({"message": "Permiso denegado"}), 401
    else:
        return jsonify({"message": "Permiso denegado"}), 401

def limpiarURL(url):
    partes=request.path.split("/")

    for laParte in partes:
        if re.search('\\d', laParte):
            url=url.replace(laParte, "?")
    return url

def validarPermiso(endPoint, metodo, idRol):
    url=dataConfig["url-backend-seguridad"] + \
        "/permiso-rol/validar-permiso/rol/" + str(idRol)
    tienePermiso=False
    headers={"Content-Type": "application/json; charset=utf-8"}
    body={"url": endPoint, "metodo": metodo}
    response=requests.get(url, json = body, headers = headers)

    try:
        data=response.json()
        if ("_id" in data):
            tienePermiso=True
    except:
        pass
    return tienePermiso

#########################################
# Redireccionamiento CRUD de candidatos #
#########################################

@ app.route("/candidatos", methods = ['GET'])
def getCandidatos():
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + '/candidatos'
    response=requests.get(url, headers = headers)
    json=response.json()
    return jsonify(json)

@ app.route("/candidatos", methods = ['POST'])
def crearCandidato():
    data=request.get_json()
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + '/candidatos'
    response=requests.post(url, headers = headers, json = data)
    json=response.json()
    return jsonify(json)

@ app.route("/candidatos/<string:id>", methods = ['GET'])
def getCandidato(id):
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + '/candidatos/' + id
    response=requests.get(url, headers = headers)
    json=response.json()
    return jsonify(json)

@ app.route("/candidatos/<string:id>", methods = ['PUT'])
def modificarCandidato(id):
    data=request.get_json()
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + '/candidatos/' + id
    response=requests.put(url, headers = headers, json = data)
    json=response.json()
    return jsonify(json)

@ app.route("/candidatos/<string:id>", methods = ['DELETE'])
def eliminarCandidato(id):
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + '/candidatos/' + id
    response=requests.delete(url, headers = headers)
    json=response.json()
    return jsonify(json)

####################################
# Redireccionamiento CRUD de mesas #
####################################

@ app.route("/mesa", methods = ['GET'])
def getMesas():
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + '/mesa'
    response=requests.get(url, headers = headers)
    json=response.json()
    return jsonify(json)

@ app.route("/mesa", methods = ['POST'])
def crearMesas():
    data=request.get_json()
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + '/mesa'
    response=requests.post(url, headers = headers, json = data)
    json=response.json()
    return jsonify(json)

@ app.route("/mesa/<string:id>", methods = ['GET'])
def getMesa(id):
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + '/mesa/' + id
    response=requests.get(url, headers = headers)
    json=response.json()
    return jsonify(json)

@ app.route("/mesa/<string:id>", methods = ['PUT'])
def modificarMesas(id):
    data=request.get_json()
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + '/mesa/' + id
    response=requests.put(url, headers = headers, json = data)
    json=response.json()
    return jsonify(json)

@ app.route("/mesa/<string:id>", methods = ['DELETE'])
def eliminarMesa(id):
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + '/mesa/' + id
    response=requests.delete(url, headers = headers)
    json=response.json()
    return jsonify(json)

#######################################
# Redireccionamiento CRUD de partidos #
#######################################

@ app.route("/partido", methods = ['GET'])
def getPartidos():
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + '/partido'
    response=requests.get(url, headers = headers)
    json=response.json()
    return jsonify(json)

@ app.route("/partido", methods = ['POST'])
def crearPartido():
    data=request.get_json()
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + '/partido'
    response=requests.post(url, headers = headers, json = data)
    json=response.json()
    return jsonify(json)

@ app.route("/partido/<string:id>", methods = ['GET'])
def getPartido(id):
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + '/partido/' + id
    response=requests.get(url, headers = headers)
    json=response.json()
    return jsonify(json)

@ app.route("/partido/<string:id>", methods = ['PUT'])
def modificarPartido(id):
    data=request.get_json()
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + '/partido/' + id
    response=requests.put(url, headers = headers, json = data)
    json=response.json()
    return jsonify(json)

@ app.route("/partido/<string:id>", methods = ['DELETE'])
def eliminarPartido(id):
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + '/partido/' + id
    response=requests.delete(url, headers = headers)
    json=response.json()
    return jsonify(json)

#########################################
# Redireccionamiento CRUD de resultados #
#########################################

@ app.route("/resultado", methods = ['GET'])
def getResultados():
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + '/resultado'
    response=requests.get(url, headers = headers)
    json=response.json()
    return jsonify(json)

@ app.route("/resultado/<string:id>", methods = ['GET'])
def getResultado(id):
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + '/resultado/' + id
    response=requests.get(url, headers = headers)
    json=response.json()
    return jsonify(json)

##########################################
# Relacion mesas-candidatos a resultados #
##########################################

@ app.route("/resultado/mesa/<string:id_mesa>/candidatos/<string:id_candidato>", methods = ['POST'])
def crearResultado(id_mesa, id_candidato):
    data=request.get_json()
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + \
        '/resultado/mesa/' + id_mesa + '/candidatos/' + id_candidato
    response=requests.post(url, headers = headers, json = data)
    json=response.json()
    return jsonify(json)

@ app.route("/resultado/<string:id>", methods = ['DELETE'])
def eliminarResultado(id):
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + '/resultado/' + id
    response=requests.delete(url, headers = headers)
    json=response.json()
    return jsonify(json)

@ app.route("/resultado/<string:id_resultado>/mesa/<string:id_mesa>/candidatos/<string:id_candidato>", methods = ['PUT'])
def modificarResultado(id_resultado, id_mesa, id_candidato):
    data=request.get_json()
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + '/resultado/' + \
        id_resultado + '/mesa/' + id_mesa + '/candidatos/' + id_candidato
    response=requests.put(url, headers = headers, json = data)
    json=response.json()
    return jsonify(json)

##############################
# Relacion candidato-partido #
##############################

@ app.route("/candidatos/<string:id>/partido/<string:id_partido>", methods = ['PUT'])
def asignarPartidoACandidato(id, id_partido):
    data=request.get_json()
    headers={"Content-Type": "application/json; charset=utf-8"}
    url=dataConfig["url-backend-registraduria"] + \
        '/candidatos/' + id + '/partido/' + id_partido
    response=requests.put(url, headers = headers, json = data)
    json=response.json()
    return jsonify(json)

######################
# Servidor corriendo #
######################

@ app.route("/", methods = ['GET'])
def test():
    json={}
    json["message"]="Servidor corriendo..."
    return jsonify(json)

#################
# Configuración #
#################

def loadFileConfig():
    with open('config.json') as f:
        data=json.load(f)
    return data

if __name__ == '__main__':
    dataConfig=loadFileConfig()
    print("Servidor corriendo: " + "http://" + \
          dataConfig["url-backend"] + ":" + str(dataConfig["port"]))
    serve(app, host = dataConfig["url-backend"], port = dataConfig["port"])
