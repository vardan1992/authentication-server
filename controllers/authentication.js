const Users = require('../models/user');

const jwt =  require('jwt-simple');

const config = require('../config');

// function for generating jwt token
function tokenForUser(user) {
    const timestamp = new Date().getTime();
   return jwt.encode({sub: user.id, iat: timestamp}, config.secret)
}

module.exports.signup = (req,res,next) => {

    const username = req.body.username;
    const password = req.body.password;

    if(!username || !password) {
        res.status(422).send({error: "Please provide Email and Password."})
    }

    Users.findOne({username}, (err,existingUser) => {
        if(err) {
            next(err);
        }
        if(existingUser){
            res.status(422).send("Email Already in use. Please use a different email address.")
        }

        const user = new Users({
            username,
            password
        });
        user.save((err) => {
            if(err) {
                next(err);
            }
            res.json({token: tokenForUser(user)}); // sending token after successfully creating a user
        });
       
    })
    
}

module.exports.signin = (req,res,next) => {
    // user is authenticated, now just send a token

    res.json({token: tokenForUser(req.user)})

}