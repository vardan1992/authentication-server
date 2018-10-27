const passport = require('passport');

const User = require('../models/user');

const config = require('../config');

const JwtStrategy =  require('passport-jwt').Strategy;

const ExtractJwt = require('passport-jwt').ExtractJwt;

const LocalStrategy = require('passport-local');

// Setup options for JWT strategy

const jwtOptions = {
    jwtFromRequest: ExtractJwt.fromHeader('authorization'),
    secretOrKey: config.secret
}

// Creating JWT Strategy

const jwtLogin = new JwtStrategy(jwtOptions , function(payload, done) {
    // check if the user is existing or not in the database
    User.findById(payload.sub, function(err, user) {
        if(err) {  // if databbase failed to connect
            return done(err, false) // 2nd argument is indicating that user is not found.
        }

        if(user) {
            done(null, true);  // user found
        } else {
            done(null, false);  // user not found.
        }
    })
})


// local strategy setup

const localOptions = {
    usernameField: 'email'
}

const localLogin = new LocalStrategy(localOptions, (email,password,done) => {
   // verify this email and password, call done with user
   // if email and password is correct
   // otherwise call done with false.

   User.findOne({username: email} , (err,user) => {
        if(err) {
            return done(err);
        }
        if(!user) {
           return done(null, false);
        }

        // compare password, Is password is equal to user.password
        user.comparePassword(password, function(err, isMatch) {
            if(err) {
                return done(err);
            }
            if(!isMatch) {
                return done(null, false);
            }

            return done(null, user);
        })
   })
})
// using the strategy

passport.use(jwtLogin);
passport.use(localLogin);