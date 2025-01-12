let username = req.query.username;

let query = "SELECT * FROM users WHERE username = '" + username + "'";
db.query(query, { type: db.QueryTypes.SELECT })
    .then(users => {
        console.log(users);
    })
    .catch(err => {
        console.error(err);
    });
