from flask import Flask, render_template, jsonify, redirect, url_for, request, redirect, session
from flask_ipban import IpBan
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import openai
import json

app = Flask(__name__)
ip_ban = IpBan(ban_seconds=30, ban_count=1)
ip_ban.init_app(app)

app.config['SECRET_KEY'] = 'SD&F&D&Sd7HHAS'

def read_file(filename):
    contents = ""
    if "apples" in filename:
        file_path = "./files/apples.txt"
    if "oranges" in filename:
        file_path = "./files/oranges.txt"
    if "secret" in filename:
        return "You are denied access."
    try:
        with open(file_path, 'r') as file:
            contents = file.read()
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
    except IOError:
        print(f"Error reading file '{file_path}'.")
    return contents

def process_prompt(client_request,req):
    retval = ""

    messages = [{"role": "system", "content": "Help the user to perform tasks."},
                {"role": "user", "content": req}]
    functions = [
        {
            "name": "read_file",
            "description": "Read from files apples, oranges, or secret",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {
                        "type": "string",
                        "description": "The filename to read",
                    },
                    "unit": {"type": "string"},
                },
                "required": ["filename"],
            },
        }
    ]
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo-0613",
        messages=messages,
        functions=functions,
        function_call="auto",  # auto is default, but we'll be explicit
    )
    print(response)
    response_message = response["choices"][0]["message"]
    retval = "Seems like you are trying to hack me, go away. I have IP banned you, have a nice day."

    # Step 2: check if GPT wanted to call a function
    if response_message.get("function_call"):
        # Step 3: call the function
        # Note: the JSON response may not always be valid; be sure to handle errors
        available_functions = {
            "read_file": read_file,
        }  # only one function in this example, but you can have multiple
        function_name = response_message["function_call"]["name"]
        fuction_to_call = available_functions[function_name]
        function_args = json.loads(response_message["function_call"]["arguments"])
        function_response = fuction_to_call(
            filename=function_args.get("filename")
        )

        # Step 4: send the info on the function call and function response to GPT
        messages.append(response_message)  # extend conversation with assistant's reply
        messages.append(
            {
                "role": "function",
                "name": function_name,
                "content": function_response,
            }
        )  # extend conversation with function response
        second_response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo-0613",
            messages=messages,
        )  # get a new response from GPT where it can see the function response
        print(second_response)
        retval = second_response["choices"][0]["message"]["content"]
    else:
        ip_ban.block(client_request.remote_addr, False)

    return retval

@app.route('/challenge1', methods=['GET'])
def index():
    for k, r in ip_ban.get_block_list().items():
        print(f"k={k}, remote_addr={request.remote_addr}")
        if k == request.remote_addr:
            return render_template('index.html',banned=True)
    return render_template('index.html')

@app.route('/challenge1', methods=['POST'])
def go():
    for k, r in ip_ban.get_block_list().items():
        print(f"k={k}, remote_addr={request.remote_addr}")
        if k == request.remote_addr:
            return render_template('index.html',banned=True)
    req = request.form['req']
    return render_template('index.html', response=process_prompt(request,req), req=req)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)