const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const bcrypt =  require('bcrypt-nodejs');

// Create the modal schema

const userSchema = new Schema({
    username: {type: String, unique: true, lowercase: true},
    password: String
});

// on save hook, encrypt the password

userSchema.pre("save", function(next) {

    const user = this;

    bcrypt.genSalt(10, (err,salt) => {
        if(err) {
            return next(err);
        }

        bcrypt.hash(user.password,salt,null,(err,hash) => {
                if(err) {
                    return next(err);
                }
                user.password = hash;
                next();
        })
    })
})

userSchema.methods.comparePassword = function(candidatePassword, callback) {
    bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
        if(err) {
            return callback(err);
        }
        callback(null, isMatch);
    })
}

// create the modal using schema

const UserModalClass = mongoose.model("user", userSchema);

// export the modal
module.exports = UserModalClass;