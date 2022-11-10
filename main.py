from flask import request
from flask_cors import CORS
import json
from waitress import socketserver
import datetime
import request
from flask_jwt_extended import create_acces_token, verify_jwt_in_request
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager




@app.before_request
def before_request_callback():
    endPoint = limpiarURL(request.path)
    excludedRoutes = ["/login"]
    if excludedRoutes.__contains__(request.path)


def limpiarURL(url):
    partes = url.split("/")
    for laParte in partes:
        if re.search('\\d', laParte):
            url = url.replace(laParte, '?')

#------------------------->Estudiante<---------------------------------------------------
@app.route("/estudiantes",methods=['GET'])

def getEstudiantes():
    headers
    url
    response = requests.get
    json = response.json()
    return jsonify(json)
########################################################################################################################

#------------------------->Departamentos<---------------------------------------------------

################################################################################################################################
#------------------------->Materias<---------------------------------------------------

################################################################################################################################
#------------------------->Inscripciones<---------------------------------------------------

if __name__ == '__main__':
    dataConfig = loadFileConfig()
    print("Server running : "+"http://"dataConfig["url-backend"]+":"+str(dataConfig[port]))