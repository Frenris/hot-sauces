const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const User = require('../models/User');

// fonction signUp pour gérer l'inscription de l'utilisateur
const signUp = (req, res, next) => {
    // déstructurer l'email et le mot de passe du corps de la requête
    const { email, password } = req.body;
    // si l'adresse e-mail ou le mot de passe n'est pas fourni, renvoie une erreur 400 Bad Request
    if (!email || !password) {
        return res.status(400).json({ error: 'Email et mot de passe sont requis' });
    }
    // hacher le mot de passe avec bcrypt
    bcrypt.hash(password, 10)
        .then(hash => {
            // créer un nouvel objet utilisateur avec l'e-mail et le mot de passe haché
            const user = new User({ email, password: hash });
            // enregistrer l'utilisateur dans la base de données
            return user.save();
        })
        .then(() => res.status(201).json({ message: 'Utilisateur créé !' }))
        .catch(error => {
            // si l'erreur est une erreur de clé en double MongoDB, renvoie une erreur 400 Bad Request
            if (error.name === 'MongoError' && error.code === 11000) {
                return res.status(400).json({ error: 'email existant déjà' });
            }
            // renvoie une erreur de serveur interne 500 pour toute autre erreur
            res.status(500).json({ error: 'Échec de la création utilisateur' });
        });
};

exports.login = (req, res, next) => {
    User.findOne({ email: req.body.email })
    .then(user => {
        if (user === null) {
            return res.status(401).json({ message: 'Paire identifiant/mot de passe incorrecte'});
        }
        bcrypt.compare(req.body.password, user.password)
            .then(valid => {
                if (!valid) {
                    return res.status(401).json({ message: 'Paire identifiant/mot de passe incorrecte' });
                }
                res.status(200).json({
                    userId: user._id,
                    token: jwt.sign(
                        { userId: user._id },
                        'RANDOM_TOKEN_SECRET',
                        { expiresIn: '24h' }
                    )
                });
            })
            .catch(error => res.status(500).json({ message: 'probleme bcrypt.compare' }));
    })
    .catch(error => res.status(500).json({ message: 'problème avec User.findOne' }));
    next();
};

// Exporter les fonctions d'inscription et de connexion en tant qu'exportations du module
module.exports = signUp;