from flask import Flask, render_template, request
from scanner_core import verificar_headers, verificar_certificado_ssl, verificar_redirecionamento_https

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    resultado = ""
    if request.method == "POST":
        url = request.form["url"]
        resultado += verificar_headers(url)
        resultado += verificar_certificado_ssl(url)
        resultado += verificar_redirecionamento_https(url)
    return render_template("index.html", resultado=resultado)

if __name__ == "__main__":
    app.run(debug=True)