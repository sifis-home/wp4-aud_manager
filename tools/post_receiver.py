from flask import Flask, request
app = Flask(__name__)

@app.route("/pub", methods=["POST"])
def result():
    print(str(request.data))
    res = {
        "result": "OK",
    }
    return res


app.run(host="localhost", port=3000)
