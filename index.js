const axios = require('axios').default;
const jose = require("jose")
const crypto = require('crypto');
const datetime = require('node-datetime');
const jwt_decode = require('jwt-decode');
var FormData = require('form-data');
var fs = require('fs');

const CLIENT_PRIVATE_KEY = `-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBell7txNDr4xYXlDeUO4ySCNRlguHisiC5nUgWDS96j4K2wPksMSA
C6RNmzaz58GPcirbCTHRkpHWhoEaTXO/U4KgBwYFK4EEACOhgYkDgYYABADijSa1
pf3o4QHKevPQ3dEcPqLQLu76K8m0fWo4dYQsaEUou8PbVlvuuMJZyuFbUPSGl+Rz
4DVE3DV1SXrCybyKYgDz2/DKYDLd8aE0YjSfQxkWmOj2Eyvktk3Yk0s/seR4ZhmH
eUhPie2ob0d7QIsC47bqnlAKllL6hPCD7QNZmt1npQ==
-----END EC PRIVATE KEY-----`;

/// Client api-key, provided by QI to client
const API_KEY = '97ad0301-869c-4481-98b6-294b139e09ae';

/// QI public key, generate by QI and provided to client
const QI_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBrhSkDcGyG1u3G47sfe5HW8Wx8egS
2ULxWgZ3aUAIG9p0+G+A7CNpZsrElTC9WQ4BoOFQZQgpqh+uj/Nf9yE14/EBUDoM
hhIek47tcCGBcbHCWsngMv0bSEfw+KRj3deWzopbI5xHj6DJZi5TrgFxF+3/GKMR
7aeiPBNb0lb0rfdNO5Q=
-----END PUBLIC KEY-----`;

const QI_AUTH_ADDRESS = 'https://api-auth.sandbox.qitech.app';
const RESPONSE_MINUTES_TOLERANCE = 5;

const file_path = '.\\identificacao_teste.pdf'

const config = {
    'main': true,
    'upload': true
}

async function qi_sign_message(
    endpoint,
    method,
    api_key,
    client_private_key,
    body=null,
    content_type="",
    additional_headers=null,
) {

    let privateKey = client_private_key
  
    privateKey = crypto.createPrivateKey({
        key: privateKey,
        format: "pem",
        type: "pkcs1",
        passphrase: "",
        encoding: "utf-8"
      })

    let md5_body = ''
    let request_body = null

    console.log(body)

    let now = new Date();
    let formated_date = now.toUTCString()

    if(body) {
        const encoded_body_token = await new jose.SignJWT(body)
        .setProtectedHeader({ alg: 'ES512' })
        .sign(privateKey)
      
        request_body = {"encoded_body": encoded_body_token}

        md5_body = crypto.createHash('md5').update(encoded_body_token).digest('hex')

    }

    const string_to_sign = (
        method + "\n" + md5_body + "\n" + content_type + "\n" + formated_date + "\n" + endpoint
    )

    const headers = {"alg": "ES512", "typ": "JWT"}
    const claims = {"sub": api_key, "signature": string_to_sign}

    const encoded_header_token = await new jose.SignJWT(claims)
        .setProtectedHeader({ alg: 'ES512' })
        .setProtectedHeader(headers)
        .sign(privateKey)

    const authorization = "QIT" + " " + api_key + ":" + encoded_header_token

    let request_header = {"AUTHORIZATION": authorization, "API-CLIENT-KEY": api_key}

    if (additional_headers) {
        request_header.update(additional_headers)
    }
    
    return {request_header, request_body}
};

async function qi_sign_upload_message(
    endpoint,
    method,
    api_key,
    client_private_key,
    body=null,
    content_type="",
    additional_headers=null,
) {

    let privateKey = client_private_key
  
    privateKey = crypto.createPrivateKey({
        key: privateKey,
        format: "pem",
        type: "pkcs1",
        passphrase: "",
        encoding: "utf-8"
      })

    let md5_body = ''
    let request_body = null

    let now = new Date();
    let formated_date = now.toUTCString()

    md5_body = await crypto.createHash('md5').update(body.toString(),  "binary").digest('hex')

    const string_to_sign = (
        method + "\n" + md5_body + "\n" + content_type + "\n" + formated_date + "\n" + endpoint
    )

    const headers = {"alg": "ES512", "typ": "JWT"}
    const claims = {"sub": api_key, "signature": string_to_sign}

    const encoded_header_token = await new jose.SignJWT(claims)
        .setProtectedHeader({ alg: 'ES512' })
        .setProtectedHeader(headers)
        .sign(privateKey)

    const authorization = "QIT" + " " + api_key + ":" + encoded_header_token

    let request_header = {"AUTHORIZATION": authorization, "API-CLIENT-KEY": api_key}

    if (additional_headers) {
        request_header.update(additional_headers)
    }
    
    return {request_header, request_body}
};

async function qi_translate_message(
    endpoint,
    method,
    api_key,
    response_body,
    response_header=null
) {

    const body = await jwt_decode(response_body['encoded_body'])

    const authorization = response_header["authorization"]
    const header_api_key = response_header["api-client-key"]

    if (header_api_key != api_key) {
        throw new Error("The api_key gathered on message's header does not match the one provided to the function")
    }

    const split_authorization = authorization.split(":")

    let authorization_api_key = split_authorization[0].split(" ")[1]

    if (authorization_api_key != api_key) {
        throw new Error("Wrong format for the Authorization header")
    }

    authorization_api_key = split_authorization[0].split(" ")[1]
    if (authorization_api_key != api_key) {
        throw new Error("The api_key gathered on message's authorization header does not match the one provided to the function")
    }

    const  header_token = split_authorization[1]
    const decoded_header_token = await jwt_decode(header_token)
    
    const signature = decoded_header_token["signature"]
    const split_signature = signature.split("\n")
    const signature_method = split_signature[0]
    const signature_md5_body = split_signature[1]
    const signature_date = split_signature[3]
    const signature_endpoint = split_signature[4]

    if (signature_endpoint != endpoint) {
        throw new Error("The api_key gathered on message's authorization header does not match the one provided to the function")
    }

    if (signature_method != method) {
        throw new Error("The api_key gathered on message's authorization header does not match the one provided to the function")
    }

    const md5_body = crypto.createHash('md5').update(response_body["encoded_body"]).digest('hex')

    if (signature_md5_body != md5_body) {
        throw new Error("The 'md5_body' parameter gathered on message's signature does not match the 'body' provided to the function")
    }

    return body

};

async function get_request(endpoint, method) {

    const url = `${QI_AUTH_ADDRESS}${endpoint}`

    let signed_request = await qi_sign_message(endpoint, method, API_KEY, CLIENT_PRIVATE_KEY)

    const request_config = {
        headers: signed_request.request_header
      };

    console.log(`URL: ${url}`)
    console.log(`Header Authorization: ${signed_request.request_header.AUTHORIZATION}`)
    console.log(`Header API-CLIENT-KEY: ${signed_request.request_header['API-CLIENT-KEY']}`)

    let response_body = null
    let respponse_header = null
    let final_response = null

    final_response = await axios.get(url, request_config)
    .then(function (response) {

        response_body = response.data
        respponse_header = response.headers
      
        translated_response = qi_translate_message(
            endpoint,
            method,
            API_KEY,
            response_body,
            respponse_header
        )

        return translated_response

    })
    .catch(function (error) {
        console.log(error)
        return null
    });

    return final_response

};

async function post_request(endpoint, method, body, content_type) {

    const url = `${QI_AUTH_ADDRESS}${endpoint}`

    let signed_request = await qi_sign_message(endpoint, method, API_KEY, CLIENT_PRIVATE_KEY, body)

    const request_config = {
        headers: signed_request.request_header
      };

    console.log(`URL: ${url}`)
    console.log(`Header Authorization: ${signed_request.request_header.AUTHORIZATION}`)
    console.log(`Header API-CLIENT-KEY: ${signed_request.request_header['API-CLIENT-KEY']}`)
    console.log(`BODY: ${signed_request.request_body}`)

    let response_body = null
    let respponse_header = null
    let final_response = null

    final_response = await axios.post(url, signed_request.request_body, request_config)
    .then(function (response) {

        response_body = response.data
        respponse_header = response.headers
      
        translated_response = qi_translate_message(
            endpoint,
            method,
            API_KEY,
            response_body,
            respponse_header
        )

        return translated_response

    })
    .catch(function (error) {
        console.log(error)
        return null
    });

    return final_response

};

async function upload_request(endpoint, method, body, content_type) {

    const url = `${QI_AUTH_ADDRESS}${endpoint}`

    var formData = new FormData();

    const readStream = await fs.createReadStream(body)
    
    body_to_send = await fs.readFileSync(body, 'binary')

    formData.append('file', readStream);

    let signed_request = await qi_sign_upload_message(endpoint, method, API_KEY, CLIENT_PRIVATE_KEY, body_to_send)

    const request_config = {
        headers: signed_request.request_header
      };

    console.log(`URL: ${url}`)
    console.log(`Header Authorization: ${signed_request.request_header.AUTHORIZATION}`)
    console.log(`Header API-CLIENT-KEY: ${signed_request.request_header['API-CLIENT-KEY']}`)
    console.log(`BODY: TOO LARGE`)

    let response_body = null
    let respponse_header = null
    let final_response = null

    final_response = await axios.post(url, formData, request_config)
    .then(function (response) {

        response_body = response.data
        respponse_header = response.headers
      
        translated_response = qi_translate_message(
            endpoint,
            method,
            API_KEY,
            response_body,
            respponse_header
        )

        return translated_response

    })
    .catch(function (error) {
        console.log(error)
        return null
    });

    return final_response

};

async function main() {

    const endpoint = `/test/${API_KEY}`
    const method = "POST"
    const body = {"name": "QI Tech"}
    const content_type = "application/json"

    const response = await post_request(endpoint, method, body, content_type)

    console.log(response)
}

async function upload() {

    const endpoint = `/upload`
    const method = "POST"
    const body = file_path
    const content_type = "application/json"

    const response = await upload_request(endpoint, method, body, content_type)

    console.log(response)
}

if(config['main']) {
    main()
}

if(config['upload']) {
    upload()
}