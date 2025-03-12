const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const cors = require('cors');// CORS middleware for enabling Cross-Origin Resource Sharing
const helmet = require('helmet');// Helmet for securing HTTP headers
const multer = require('multer');
const GridFsStorage = require('multer-gridfs-storage'); // GridFS storage engine for Multer
const {Server} = require('server.io');// Server.io for real-time communication
const redis = require('redis'); // Redis client for interacting with Redis server
const Queue = require('bull'); // Bull for job queueing
const request = require('supertest'); // Supertest for HTTP assertions
require('dotenv').config();

const app = express();

// Creating an HTTP server and attaching the Express app to it
const server = require('http').createServer(app);

// Creating a new Server.io instance for real-time communication
const io= new Server(server, {cors:{origin: '*'}});
const redisClient = redis.createClient();

// Creating a new job queue with Bull, connecting to Redis
const jobQueue =new Queue('jobQueue', {redis: {host: '127.0.0.1', port:6379}});
app.use(express.json());
app.use(cors());

// Middleware to secure HTTP headers
app.use(helmet());


//databse connection
mongoose.connect(process.env.Mono_uri, {useNewUrlParser:true, useUnifiedTopology:true})
        .then(()=>console.log("Database connected successfully"))
        .catch(err=> console.log(err))

//schema creation
const UserSchema = new mongoose.Schema({
    name:String,
    email:String,
    password:String,
    role:{
        type: String,
        enum:['user', 'admin'],// Role can only be 'user' or 'admin'
        default: 'user' // Default role is 'user'
    }
    //Role-Based: Yes, this schema is role-based as it includes a role field that can be either 'user' or 'admin'. This can be used to implement role-based access control (RBAC) in your application, where different roles have different permissions and access levels.
});
const User = mongoose.model('User', UserSchema);

//Routes
app.post('/register', async(req,res)=>{
    const {name, email, password} = req.body;
     // Hash the password with bcrypt, using a salt round of 10
    const hashPassword = await bcrypt.hash(password, 10);
    const user = new User({name, email, password: hashPassword});
    await user.save();
    res.status(201).json({message : "user created successfully"});
});

app.post('/login', async(req,res)=>{
    const {email, password} = req.body;
    const  user = await User.findOne({email});
    if(!user){
       return res.status(400).json({message: 'User not found'})
    }
    const compare = await bcrypt.compare(password, user.password)
    if(!compare){
       return res.status(400).json({message: 'Invalid credentials'})
    }
    // Generate a JWT token with the user's ID and role, expiring in 1 hour
    const token = jwt.sign({id:user._id, role:user.role}, 'reveal', {expiresIn: '1h'});
    res.json({message: 'Login successful', token});

})

//Protected Route using middleware function
app.get('/dashboard', verifytoken, async(req,res)=>{
    res.json({message: 'Dashboard accessed successfully', user: req.user});
})

verifytoken = (req,res,next)=>{
    const token = req.header('x-auth-token');
    if(!token){
        return res.status(401).json({message: 'Access denied, token missing'});
    }
    try {
        const verify = jwt.verify(token, 'reveal');
        req.user = verify
        //why req.user?
        //If the token is valid, attaches the decoded token to user. 
    } catch (error) {
        res.status(400).json({message: 'Token is not valid'})
    }
}

//File upload using multer
// Initialize GridFsStorage with the MongoDB connection URL
const storage = new GridFsStorage({url:Mongo_url});
// Initialize Multer with the GridFsStorage engine
const upload = multer({storage});
app.post('/upload', upload.single('file'), (req,res)=>{
    // Respond with the uploaded file information
    res.json({file:req.file});
})


//websocket connection
//listen for a new connection to the socket server
io.on('connection', (socket)=>{
    //upon new connection, listen for the 'message' from connected client
    socket.on('message', (data)=>{
        //when received 'message' show to all connected clients
        io.emit('message', data)
    });
    //if disconnected show message disconnected
    socket.on('disconnect', ()=> console.log('User disconnected'))
});

//Redis caching

app.get('/cached-data', async(req, res)=>{
    // Retrieve data from Redis cache with the key 'someData'
    redisClient.get('someData', async(err,data)=>{
        if(data){
            // If data is found in the cache, return it to the client
            return res.json({fromCache:true, data:JSON.parse(data)});
        }
        // If data is not found in the cache, create new data
        const newData={ message:'This is fresh data' };
        // Store the new data in the Redis cache with an expiration time of 3600 seconds (1 hour)
        redisClient.setex('someData', 3600, JSON.stringify(newData));
        // Respond with the new data, indicating it is not from the cache
        res.json({fromCache:false, data:newData})

    });
});

//Job queueing with Bull
// Define a processor for the job queue
jobQueue.process(async (job) => {
    console.log('Processing job:', job.data);
  // Return a resolved promise to indicate the job is processed successfully
    return Promise.resolve();
});
// Define a POST endpoint for enqueuing jobs
app.post('/enqueue-job', async (req, res) => {
  // Add a new job to the job queue with the specified task data
    await jobQueue.add({ task: 'Background task' });
  // Respond with a success message indicating the job was enqueued
    res.json({ message: 'Job enqueued' });
});

//Testing with Jest and Supertest
if(node_env==='test'){
    module.exports=app
}else{
    const PORT = 5000;
    server.listen(PORT, ()=> console.log(`Server Running on ${PORT}`));
}