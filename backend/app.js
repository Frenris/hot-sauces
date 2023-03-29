const express = require('express');
const mongoose = require('mongoose');

const app = express();

const userRoutes = require('./routes/user');

mongoose.connect('mongodb+srv://fredericdemeaux:D&cheance2017@hot-takes.mhna1vz.mongodb.net/?retryWrites=true&w=majority',
  { useNewUrlParser: true,
    useUnifiedTopology: true })
  .then(() => console.log('Connexion à MongoDB réussie !'))
  .catch(() => console.log('Connexion à MongoDB échouée !'));

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content, Accept, Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    next();
  });

app.use((req, res, next) => {
    console.log('Requête reçue !');
    next();
  });
  
app.use((req, res, next) => {
    res.status(201);
    next();
  });
  
app.use((req, res, next) => {
    res.json({ message: 'Votre requête a bien été reçue !' });
    next();
  });
  
app.use((req, res, next) => {
    console.log('Réponse envoyée avec succès !');
    next();
  });

app.use('/api/auth', userRoutes);

module.exports = app;