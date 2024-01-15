const express = require("express");
const mysql = require("mysql");
const fileuploader = require("express-fileupload");
const path = require("path");
const cors = require("cors");
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
var cookieParser = require("cookie-parser");
require('dotenv').config();


var app = express();
app.use(
    cors({
        origin: ['http://localhost:3000'],
        methods: ['GET', 'POST', 'DELETE'],
        credentials: true,
    })
);
app.use(express.json());
app.use(cookieParser());
app.use(express.static("public"));

app.use(express.urlencoded("true"));

app.use(fileuploader());

app.listen(2000, function () {
    console.log("Server Started");
});
//========for databas configuration=========
const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    dateStrings: true,
};

//========for Databse Refer===================
var dbRef = mysql.createConnection(dbConfig);
dbRef.connect(function (err) {
    if (err == null)
        console.log("Connected Successfully");
    else
        console.log(err);
});

//===================================== Verify User Code ===========================================================

const verifyUser = (req, res, next) => {
    console.log(" req Token is", req.cookies.token);

    const token = req.cookies.token;
    console.log("Token is", token);
    if (!token) {
        return res.status(201).json("Token is missing");
    } else {
        jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
            if (err) {
                return res.status(201).json("Error with token");
            } else {
                const userType = decoded.userType;
                console.log(userType);
                if (userType === "client" || userType === "admin") {
                    // User has the 'admin' role, so allow access
                    req.email = decoded.email;
                    next();
                } else {
                    // User does not have the 'admin' role, so deny access
                    return res.status(201).json("Access denied. Requires user role");
                }
            }
        });
    }
};

//===================================== SignUp Code ===========================================================
app.post("/signup", async (req, res) => {

    dbRef.query("SELECT Email FROM users WHERE Email=?", [req.body.email], async function (err, TableJsonAry) {
        if (err) {
            console.error("Error: ", err);
            res.status(500).json("Internal Server Error");
        }
        else if (TableJsonAry.length === 1) {
            console.log("Email Not Found");
            return res.status(400).json({ message: "Email Already Exist" });
        } else if (TableJsonAry.length === 0) {
            const { name, email, password } = req.body;

            try {
                // Hash the password using bcrypt
                const saltRounds = 10;
                const hashedPassword = await bcrypt.hash(password, saltRounds);

                // Insert user with hashed password
                dbRef.query("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", [name, email, hashedPassword], function (err, TableJsonAry) {
                    if (err) {
                        console.error("Error: ", err);
                        res.status(500).json("Internal Server Error");
                    } else {
                        dbRef.query("SELECT * FROM users WHERE Email=?", [req.body.email], async function (err, TableJsonAry) {
                            if (err) {
                                console.error("Error: ", err);
                                res.status(500).json("Internal Server Error");
                            }
                            else if (TableJsonAry.length === 1) {
                                console.log(TableJsonAry[0]);
                                console.log('password from db is:', TableJsonAry[0].Password);
                                console.log('password from forntend is:', req.body.password);

                                // Compare the entered password with the hashed password
                                const passwordMatch = await bcrypt.compare(req.body.password, TableJsonAry[0].Password);
                                console.log("Encrypted pass is", passwordMatch);
                                if (!passwordMatch) {
                                    return res.status(400).json({ message: "Invalid Password" });
                                }
                                const token = jwt.sign({ userId: TableJsonAry[0].id, userType: TableJsonAry[0].type, email: TableJsonAry[0].Email }, process.env.JWT_SECRET, { expiresIn: '1h' });

                                // Set the token as a cookie or in the response headers
                                res.cookie("token", token);
                                // Successful login
                                res.status(200).json({ message: "Sign Up Successful", token });
                            }
                        })
                    }
                });

            } catch (error) {
                console.error("Error:", error);
                res.status(500).json("Internal Server Error");
            }
        }
    })


});
//=================================================== Login Code =========================================================================
app.post("/login", async (req, res) => {
    dbRef.query("SELECT * FROM users WHERE Email=?", [req.body.email], async function (err, TableJsonAry) {
        if (err) {
            console.error("Error: ", err);
            res.status(500).json("Internal Server Error");
        }
        else if (TableJsonAry.length === 0) {
            console.log("Email Not Found");
            return res.status(400).json({ message: "Email Not Found" });
        } else if (TableJsonAry.length === 1) {
            console.log(TableJsonAry[0]);
            console.log('password from db is:', TableJsonAry[0].Password);
            console.log('password from forntend is:', req.body.password);

            // Compare the entered password with the hashed password
            const passwordMatch = await bcrypt.compare(req.body.password, TableJsonAry[0].Password);
            console.log("Encrypted pass is", passwordMatch);
            if (!passwordMatch) {
                return res.status(400).json({ message: "Invalid Password" });
            }
            // Successful login
            // Generate JWT token
            const token = jwt.sign({ userId: TableJsonAry[0].id, userType: TableJsonAry[0].type, email: TableJsonAry[0].Email }, process.env.JWT_SECRET, { expiresIn: '1h' });

            // Set the token as a cookie or in the response headers
            res.cookie("token", token);
            // Successful login
            res.status(200).json({ message: TableJsonAry[0].type, token });
        }
    }
    )
})


//=================================================== Submit Data Code =========================================================================
// app.get("/fetchuserid", function (req, res) 
//     // const {loginemail} =  req.body.loginemail;
//     console.log("data from db is", req.body.loginemail);

//     dbRef.query("SELECT * FROM users WHERE Email=?", [req.query.loginemail], function (err, TableJsonAry) {
//         if (err)
//             res.status(400).json(err);
//         else
//             res.status(200).json(TableJsonAry);
//         console.log(TableJsonAry);
//     })
// })


app.post("/savedata", verifyUser, function (req, res) {
    console.log("data from frontend is 1", req.files.profileImage.name);

    let picname = "NOT UPLOADED";
    if (req.files != null) {
        picname = req.files.profileImage.name;
        console.log("File Name=" + picname);

        var des = path.join(__dirname, "public", "Assets", "profile", picname);
        req.files.profileImage.mv(des, function (err) {
            if (err)
                console.log(err);
            else
                console.log("Upload Successful");
        })//saving in uploads folder

    }

    console.log("data from frontend is 2==========", req.body);
    const data = [
        req.body.username,
        req.body.loginemail,
        picname,
        req.body.fullname,
        req.body.companyname,
        req.body.title,
        req.body.website,
        req.body.number,
        req.body.email,
        req.body.linkdin,
        req.body.facebook,
        req.body.instagram,
    ];

    dbRef.query("SELECT User_Name from userdetails WHERE User_Name =?", [req.body.username], function (err, TableJsonAry) {
        if (err) {
            console.error("Error checking existing username:", err);
            res.status(500).json("=========Internal Server Error========");
        } else if (TableJsonAry.length > 0) {
            res.status(400).json({ message: "Username Already Exists. Kindly Change It" });
        } else {
            dbRef.query("INSERT INTO userdetails (User_Name, Login_Email,Profile_Pic, Name, Company, Title, Website_Link, Number, Email, Linkdin_Link, Facebook_Link, Instagram_Link) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                data, function (err, TableJsonAry) {
                    if (err) {
                        console.error("Error inserting data:", err);
                        res.status(500).json("Internal Server Error");
                    } else
                        res.status(200).json("Data Stored");
                    console.log("data inserted");
                });
        }
    });
});

//==================================== For Card Display Code =============================================================

app.get("/fetch", function (req, res) {
    console.log(`data from db is ${req.body}`);
    dbRef.query("SELECT * FROM userdetails WHERE User_Name=?", [req.query.user_name], function (err, TableJsonAry) {
        if (err)
            res.status(400).json(err);
        else
            res.status(200).json(TableJsonAry);
    })

})
//=================================================== Update Data Code =========================================================================


app.get("/fetchdata", verifyUser, function (req, res) {
    console.log("email from token", req.email);

    dbRef.query("SELECT * FROM userdetails WHERE Login_Email=?", [req.email], function (err, TableJsonAry) {
        if (err)
            res.status(400).json(err);
        else
            res.status(200).json(TableJsonAry);
        console.log(TableJsonAry);
    })
})

app.post("/update", function (req, res) {

    let picname
    console.log("files are", req.files);
    if (req.files != undefined) {
        picname = req.files.profileImage.name;
        console.log("File Name=" + picname);

        var des = path.join(__dirname, "public", "Assets", "profile", picname);
        req.files.profileImage.mv(des, function (err) {
            if (err)
                console.log(err);
            else
                console.log("Upload Successful");
        })//saving in uploads folder
        update(req, res, picname);

    }
    else {
        console.log(`login email is ${req.body.loginemail}`);
        dbRef.query("SELECT Profile_Pic FROM userdetails WHERE Login_Email=?", [req.body.loginemail], function (err, TableJsonAry) {
            if (err)
                res.status(400).json(err);
            else {
                console.log(`old pic is ${TableJsonAry[0].Profile_Pic}`);
                picname = TableJsonAry[0].Profile_Pic;
                update(req, res, picname);
            }
        })
    }
    console.log(`pic name is ${picname}`);
    console.log(`aashim`)
});

function update(req, res, picname) {
    console.log("update query")
    dbRef.query(
        "UPDATE userdetails SET Profile_Pic=?, Name=?, Company=?, Title=?, Website_Link=?, Number=?, Email=?, Linkdin_Link=?, Facebook_Link=?, Instagram_Link=? WHERE Login_Email=? AND User_Name=?",
        [
            picname,
            req.body.fullname,
            req.body.companyname,
            req.body.title,
            req.body.website,
            req.body.number,
            req.body.email,
            req.body.linkdin,
            req.body.facebook,
            req.body.instagram,
            req.body.loginemail,
            req.body.username,

        ],
        function (err, TableJsonAry) {
            if (err) {
                console.error("Error updating data:", err);
                res.status(500).json("Internal Server Error");
            }

            res.status(200).json("Data Updated");
        }
    );
}


//==================================== Forgot Password Code =============================================================

app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    console.log(`email is ${req.body.email}`)
    try {
        await dbRef.query("SELECT * from users WHERE email=?", email, function (err, TableJsonAry) {
            if (err) {
                console.error("Error: ", err);
                res.status(500).json("Internal Server Error");
            } else if (TableJsonAry.length === 0) {
                res.status(400).json({ message: "Invalid Email Address" });
            } else {
                const token = jwt.sign({ useremail: TableJsonAry[0].email }, process.env.JWT_SECRET, { expiresIn: '1h' });
                sendResetEmail(TableJsonAry[0].Email, token)
                    .then((result) => {
                        return res.status(200).json({ message: "Password reset link sent to your email address" });
                    })
                    .catch((error) => {
                        res.status(500).json({ message: 'Something went wrong. Please try again later.' });
                    })
            }
        })
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'Something went wrong. Please try again later.' });
    }
});


async function sendResetEmail(email, token) {
    try {
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: 'gargaashim123@gmail.com',
                pass: 'zcczzptufnaehotr',
            },
        });

        const mailOptions = {
            from: 'gargaashim123@gmail.com',
            to: email,
            subject: 'Reset your password',
            html: `
                <p>We received a request to reset your password.</p>
                <p>Please click the link below to create a new password:</p>
                <a href=${`http://localhost:3000/resetpassword/${email}/${token}`}>Reset Password</a>
                <p>This link will expire in 1 hour.</p>
                <p>If you didn't request a password reset, please ignore this email.</p>
                <p>Sincerely,</p>
                <p>Your App Team</p>
            `,
        };

        await transporter.sendMail(mailOptions);

    } catch (error) {
        console.error('Error sending email:', error);
        throw new Error('Failed to send email');
    }
}



//=========================================Reset Password Code======================================
async function retrieveUserData(email) {
    try {
        const [userData] = await dbRef.query('SELECT * FROM users WHERE Email = ?', [email]);
        return userData;
    } catch (error) {
        console.error('Error retrieving user data:', error);
        throw new Error('User not found');
    }
}

async function verifyResetToken(token, userData) {
    try {
        const decodedToken = jwt.verify(token, process.env.JWT_SECRET);

        // Compare token data with user data:
        const { useremail, resetTokenExpiry } = decodedToken;

        if (useremail !== userData.email) {
            return false; // Email mismatch
        }

        // Check for token expiration:
        if (Date.now() > resetTokenExpiry) {
            return false; // Token expired
        }

        // Optionally, check token against a stored hash:
        if (userData.resetToken !== token) {
            return false; // Token doesn't match stored value
        }

        return true; // Token is valid
    } catch (error) {
        console.error('Error verifying token:', error);
        return false;
    }
}

app.get('/reset-password/:email/:token', async (req, res) => {
    try {
        const { email, token } = req.params;
        const userData = await retrieveUserData(email);
        const isValidToken = await verifyResetToken(token, userData);

        if (isValidToken) {
            res.render('reset-password', { email, token });
        } else {
            res.status(400).json({ message: 'Invalid reset token or user not found' });
        }
    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
});

app.post("/reset-password", async (req, res) => {
    try {
        const { password, email, token } = req.body;

        jwt.verify(token, process.env.JWT_SECRET, async (err, decoded) => {
            if (err) {
                return res.status(400).json({ message: 'Error with token' });
            }

            // Hash the new password before updating it in the database
            const hashedPassword = await bcrypt.hash(password, 10);

            dbRef.query('UPDATE users SET Password = ? WHERE Email = ?', [hashedPassword, email], (error, result) => {
                if (error) {
                    // Handle error
                    console.error('Error updating password:', error);
                    return res.status(400).json({ message: 'Invalid reset token or error updating password' });
                }

                // Handle success
                console.log('Password updated successfully:', result);
                res.status(200).json({ message: 'Password updated successfully' });


            });
        });
    } catch (error) {
        console.error('Error:', error);
        res.status(400).json({ message: 'Invalid reset token or error updating password' });
    }
});

//================================================== For Admin Panel ==================================================================== 

app.get("/allusers", function (req, res) {
    console.log(`data from db is ${req.body}`);
    dbRef.query("SELECT * FROM users", function (err, TableJsonAry) {
        if (err)
            res.status(400).json(err);
        else
            res.status(200).json(TableJsonAry);
    })

})


//======================================================= Delete User================================================================

app.delete("/deleteUser/:email", function (req, res) {
    dbRef.query("DELETE FROM users WHERE Email=?", [req.params.email], function (err, result) {
        if (err) { res.status(400).json(err); }
        else {
            res.status(200).json(result);
        }

    })
})