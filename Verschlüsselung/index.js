const express = require('express');
const bodyParser = require('body-parser');
const jsonParser = bodyParser.json();
const rot13 = require('ebg13');
const NodeRSA = require('node-rsa');

const app = express();
app.post('/rot13', jsonParser, function (req, res) {
    const text = req.body.text;
    if ( typeof text !== 'string' || text === '' ) {
        res.status(400);
        res.send({ message: "The given body is invalid. Schema required: { text: string }" }) 
    } else {
        const cypher = rot13(text);
        res.send({ cypher })
    }
});

app.post("/caesar/cypher", jsonParser, function (req, res ){
    const text = req.body.text;
    const key = req.body.key;
    if ( typeof text !== 'string' || text === '' || key <= 0 || key > 26 ) {
        res.status(400);
        res.send({ message: "The given body is invalid. Schema required: { text: string, key: number }" }) 
    } else {
        const cypher = rot13(text, key);
        res.send({ cypher })
    }
});

app.post("/caesar/decypher", jsonParser, function (req, res){
    const text = req.body.text;
    const key = req.body.key;
    if ( typeof text !== 'string' || text === '' || key <= 0 || key > 26 ) {
        res.status(400);
        res.send({ message: "The given body is invalid. Schema required: { text: string, key: number }" }) 
    } else {
        const cypher = rot13(text, 26 - key);
        res.send({ cypher })
    }

});

app.get("/rsa/generate-keypair", function (req, res){
    const key= new NodeRSA({b: 256});
    
    res.send({
        private: key.exportKey("private"),
        public: key.exportKey("public")
    });
});

app.post("/rsa/encrypt", jsonParser, function(req, res){
    const text = req.body.text;
    const key = req.body.key;
    if ( typeof text !== 'string' || text === '' || typeof key !== "string" ) {
        res.status(400);
        res.send({ message: "The given body is invalid. Schema required: { text: string, key: PEM }" }) 
    } else { 
    const rsaKey = new NodeRSA(key, "public");

    const cypher = rsaKey.encrypt(text);

    res.send({cypher});
    }


});

app.post("/rsa/decrypt", jsonParser, function(req,res){
    const text = req.body.text;
    const key = req.body.key;
    if ( typeof text !== 'string' || text === '' || typeof key !== "string" ) {
        res.status(400);
        res.send({ message: "The given body is invalid. Schema required: { text: string, key: PEM }" }) 
    } else {
    const rsaKey = new NodeRSA(key, "private");

    const cypher = rsaKey.decrypt(text);

    res.send({plain});
    }

});


app.listen(4000)


