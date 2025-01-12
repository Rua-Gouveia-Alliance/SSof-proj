userId = req.body.userId;

db.query("DELETE FROM users WHERE id = " + userId, function(err) {
    if (err) throw err;
    console.log("Account deleted");
});
