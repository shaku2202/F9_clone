//Feedback route
const express = require("express");
const { FeedbackModel } = require("../models/feedback.model");
const { auth } = require("../middlewares/auth.middleware");

const feedbackRoute = express.Router();

feedbackRoute.get("/", async (req, res) => {
  const page = req.query.page || 1;
  const limit = req.query.limit || 10;
  const skip = page * limit - limit;
  try {
    const feedbacks = await FeedbackModel.find().sort({ updatedAt: -1 }).skip(skip).limit(limit);
    res.header("X-Total-Count", await FeedbackModel.countDocuments());
    if (feedbacks.length === 0) {
      res.json({ msg: "No feedback found" });
      console.log("No feedback");
    }
    res.status(200).json({ feedbacks });
  } catch (error) {
    res.status(400).json({ error });
  }
});

feedbackRoute.post("/add", auth, async (req, res) => {
  const payload = req.body;
  try {
    const feedback = new FeedbackModel(payload);
    await feedback.save();
    res.status(201).json({ msg: "Your feedback has been created" });
  } catch (error) {
    res.status(400).json({ error });
  }
});

module.exports = {
  feedbackRoute,
};

//Question answer Routes
const express=require('express');
const answerRouter=express.Router();
const{AnswerModel}=require('../models/answer.model')
const{auth}=require('../middlewares/auth.middleware')
const{VoteModel}=require('../models/vote.model')

answerRouter.use(auth)
answerRouter.get('/:questionid',async(req,res)=>{
    const questionID=req.params.questionid
try{
    const upvote='upvote'; 
const answer=await AnswerModel.find({questionID}).sort({[upvote]:'desc'})
res.status(200).json(answer);
}catch(err)
{
    res.status(400).json({error:err});
}
})


answerRouter.post('/create/:questionid',async(req,res)=>{
    const questionID=req.params.questionid
const{content}=req.body
try{
const answer=new AnswerModel({content,questionID,userID:req.body.userID,username:req.body.username})
await answer.save();
res.status(200).json({msg:'new answer has been added'})
}
catch(err)
{
    res.status(400).json({error:err});
}
})

answerRouter.delete('/delete/:id',async(req,res)=>{
    const _id=req.params.id;
    const{userID}=req.body;
    const answer= await AnswerModel.findOne({_id})
    if(userID===answer.userID)
    {
    try{
        await AnswerModel.findByIdAndDelete(_id);
        res.status(200).json({msg:'answer has been deleted'});
        }
        catch(err){
        res.status(400).json({error:err})
        }
    }
    else{
    res.json({msg:'you are not authorised'});
    }
    })


    answerRouter.patch('/upvote/:answerID',async(req,res)=>{
        const answerID=req.params.answerID
        const {userID}=req.body
        try{
            const vote = await VoteModel.findOne({ $and: [{ userID }, { answerID }] });
            if(vote)
            {
                res.status(200).json({msg:'you can only vote once'})
            }
            else{
                const addvote=new VoteModel({userID,answerID})
                await addvote.save()
                const answer=await AnswerModel.findOne({_id:answerID})
                let number=answer.upvote
                number+=1;
                await AnswerModel.findByIdAndUpdate(answerID,{upvote:number})
                res.status(200).json({msg:'upvote has beeen increased'})
            }
        }
        catch(err)
        {
            res.status(400).json({error:err})
        }
    })

    answerRouter.patch('/downvote/:answerID',async(req,res)=>{
        const answerID=req.params.answerID
        const {userID}=req.body
        try{
            const vote = await VoteModel.findOne({ $and: [{ userID }, { answerID }] });
            if(vote)
            {
                res.status(200).json({msg:'you can only vote once'})
            }
            else{
                const addvote=new VoteModel({userID,answerID})
                await addvote.save()
                const answer=await AnswerModel.findOne({_id:answerID})
                let number=answer.upvote
                number-=1;
                await AnswerModel.findByIdAndUpdate(answerID,{upvote:number})
                res.status(200).json({msg:'you downvoted the user'})
            }
        }
        catch(err)
        {
            res.status(400).json({error:err})
        }
    })


module.exports={
    answerRouter
};
//Payment routes

require("dotenv").config();
const express = require("express");
const { auth } = require("../middlewares/auth.middleware");

const paymentRouter = express.Router();

// paymentRouter.use(auth);


const stripe = require('stripe')("sk_test_51OaAZqSJU9EFf2GWhLQSpolsUd4LXyrYZtnWBaTT7gL5h7DBUZ4aLYdxre9tRSjQbw9oib16YUc5xdR3bhJVy1LV00z0mqlIpz")

paymentRouter.post('/', async (req, res) => {
  try {

    const { product } = req.body;

    const lineItems = product.map((product) => ({
      price_data: {
        currency: 'usd',
        product_data: {
          name: product.plan,
        },
        unit_amount: product.price * 100
      },
      quantity: product.qnty
    }))

    const session = await stripe.checkout.sessions.create({
      line_items: lineItems,
      mode: 'payment',
      success_url: "https://tracker-jet-app.vercel.app/dashboard/dashboard.html",
      cancel_url: "https://www.yahoo.com",
    });

    res.json({ id: session.id })

  } catch (e) {
    return res.status(400).send({
      error: {
        message: e.message,
      },
    });
  }
});

module.exports = {
  paymentRouter,
};
//Question routes 
const express=require('express');
const questionRouter=express.Router();
const{QuestionModel}=require('../models/question.model')
const{auth}=require('../middlewares/auth.middleware')

questionRouter.use(auth)
questionRouter.get('/mine',async(req,res)=>{
try{
const question=await QuestionModel.find({userID:req.body.userID})
res.status(200).json(question);
}catch(err)
{
    res.status(400).json({error:err});
}
})
questionRouter.get('/:questionid',async(req,res)=>{
    const _id=req.params.questionid
    try{
    const question=await QuestionModel.findOne({_id})
    res.status(200).json(question);
    }catch(err)
    {
        res.status(400).json({error:err});
    }
    })


questionRouter.get('/',async(req,res)=>{
    const search=req.query.search || "";
    const limit=5;
    const page=parseInt(req.query.page)||0
    try{
        const createdAt = 'createdAt';
        const totalQuestions = await QuestionModel.countDocuments({
            title: { $regex: search, $options: 'i' }
        });
    const question=await QuestionModel.find({title:{$regex:search,$options:'i'}}).sort({[createdAt]:'desc'}).skip(limit*page).limit(limit)
    res.status(200).json({question,totalQuestions});
    }catch(err)
    {
        console.log(err)
        res.status(400).json({error:err});
    }
    })

questionRouter.post('/create',async(req,res)=>{
const{title,body,userID,username,tags}=req.body
try{
const question=new QuestionModel({title,body,userID,username,tags})
await question.save();
res.status(200).json({msg:'new question has been created'})
}
catch(err)
{
    console.log(err)
    res.status(400).json({error:err});
}
})


questionRouter.delete('/delete/:id',async(req,res)=>{
const _id=req.params.id;
const{userID}=req.body;
const question= await QuestionModel.findOne({_id})
if(userID===question.userID)
{
try{
    await QuestionModel.findByIdAndDelete(_id);
    res.status(200).json({msg:'question has been deleted'});
    }
    catch(err){
    res.status(400).json({error:err})
    }
}
else{
res.json({msg:'you are not authorised'});
}
})

module.exports={
    questionRouter
};
//Quotes route 
const express = require('express');

const Quote = require('../models/quotes.models');
const quoteRouter = express.Router();
// Get all quotes
quoteRouter.get('/', async (req, res) => {
    try {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 5;
  
      const startIndex = (page - 1) * limit;
      const endIndex = page * limit;
  
      const quotes = await Quote.find().limit(limit).skip(startIndex);
  
      const pagination = {};
      if (endIndex < (await Quote.countDocuments().exec())) {
        pagination.next = {
          page: page + 1,
          limit: limit
        };
      }
  
      res.status(200).json({
        msg: "Paginated Quotes",
        quotes: quotes,
        pagination: pagination
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });
  

quoteRouter.post('/add', async (req, res) => {
  try {
    const { text, author } = req.body;
    const newQuote = new Quote({ text, author });
    await newQuote.save();
    res.status(200).json({msg:"Quotes saved"})
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

module.exports = {quoteRouter};
//task routes
const express = require("express");
const { auth } = require("../middlewares/auth.middleware");
const { TaskModel } = require("../models/task.model");

const taskRoute = express.Router();

taskRoute.use(auth);

taskRoute.get("/", async (req, res) => {
  const category = req.query.category || null;
  try {
    const tasks = category
      ? await TaskModel.find({ userID: req.body.userID, category })
      : await TaskModel.find({ userID: req.body.userID });
    if (tasks.length === 0) throw "Please create some tasks first";
    res.status(200).json({ tasks });
  } catch (error) {
    res.status(400).json({ error: "some error" });
  }
});

taskRoute.post("/add", async (req, res) => {
  const payload = req.body;
  if (req.query.category) payload.category = req.query.category;
  try {
    const task = new TaskModel(payload);
    await task.save();
    res.status(201).json({ msg: "New task has been created" });
  } catch (error) {
    res.status(400).json({ error });
  }
});

taskRoute.patch("/update/:taskID", async (req, res) => {
  const payload = req.body;
  try {
    const taskFound = await TaskModel.findOne({ _id: req.params.taskID });
    console.log(taskFound);
    console.log(payload.userID, taskFound.userID);
    if (payload.userID !== taskFound.userID)
      throw "Unauthorized: You're not authorized to change this task.";
    let status = taskFound.status;
    if (status) taskFound.status = false;
    else taskFound.status = true;
    await TaskModel.findByIdAndUpdate(req.params.taskID, taskFound);
    res.status(201).json({ msg: "The task has been updated successfully" });
  } catch (error) {
    res.status(400).json({ error });
  }
});

taskRoute.delete("/update/:taskID", async (req, res) => {
  try {
    if (req.body.userID !== req.params.taskID)
      throw "Unauthorized: You're not authorized to delete this task.";
    await TaskModel.findByIdAndUpdate(req.params.taskID, payload);
    res.status(201).json({ msg: "The task has been updated successfully" });
  } catch (error) {
    res.status(400).json({ error });
  }
});

module.exports = {
  taskRoute,
};
//user routes 
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const {UserModel} = require("../models/user.model");
const {OtpVerificationModel} = require("../models/otpverification.model");
require("dotenv").config();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const express = require("express");
const { use } = require("bcrypt/promises");
const {BlacklistModel} = require("../models/blacklist.model")

// const { use } = require("bcrypt/promises");
const userRouter = express.Router();
// Register

const transporter = nodemailer.createTransport({
    service: "gmail",
    port: 465,
  secure: true,
    auth: {
      // TODO: replace `user` and `pass` values from <https://forwardemail.net>
      user: process.env.AUTH_EMAIL,
      pass: process.env.AUTH_PASS,
    },
  });
transporter.verify((err,success)=>{
    if(err){
        console.log(err);
    }else{
        console.log("ready for message");
        console.log(success);
    }
})

userRouter.post("/register", async (req, res) => {
    const { name, email, password } = req.body;
    const user = await UserModel.findOne({ email });
    if (user) {
      res.json({ msg: "Email already used!" });
    } else {
      const salt = 3;
      bcrypt.hash(password, salt)
        .then((hashPass) => {
          const newUser = new UserModel({ name, email, password: hashPass,verified:false });
          newUser.save()
            .then((result) => {
              sendOtpVerificatiionEmail(result,res);
            })
            .catch((err) => {
              res.json({ err });
            });
        });
    }
  });
  
   
const sendOtpVerificatiionEmail = async({_id,email},res)=>{
    try{
      const otp = `${Math.floor(1000+Math.random()*9000)}`;


    const mailOptions = {
        from:process.env.AUTH_EMAIL,
        to:email,
        subject:"Verify your Email",
        html:`<p>Enter <b>${otp}</b> in the app to verify your email </p>
        <p>This code <b>expires in 1 hour</b>.</p>`,
    };
    const saltRound = 10;
    const hashedOTP = await bcrypt.hash(otp,saltRound);
    const newOTPVerification = await new OtpVerificationModel({
        email:email,
        otp:hashedOTP,
        createdAt:Date.now(),
        expiresAt:Date.now()+3600000
    });
    await Promise.all([newOTPVerification.save(),
    transporter.sendMail(mailOptions)])
    res.status(200).json({
        status:"PENDING",
        message:"Verification otp email sent",
        data:{
            userId:_id,
            email,
        },
    })
    }
    catch(err){
       res.status(400).json({
        msg:err.message,
       })
    }
}

// Verify email
// userRouter.get("/verify/:userId/:otp",(req,res)=>{
//     let { userId, otp} = req.params;
//     const hashedOTP =  bcrypt.hash(otp,10)
//     let optPresent = OtpVerificationModel.find({userId})
//     .then((result)=>{
//         if(optPresent){
//             bcrypt.compare(hashedOTP,otp)
//             .then(result=>{
//                 if(result){
//                    UserModel.updateOne({_id:userId}, {verified:true})
//                    .then(()=>{
//                     OtpVerificationModel.deleteOne({userId})
//                     .then(()=>{
//                         res.json({msg:"Verification successfull"})
//                     }).catch(err=>{res.json(err)})
//                    })
//                    .catch(err=>{res.json({err})})
//                 }else{
//                     res.json({msg:"Incorrect OTP"})
//                 }
//             })
//             .catch(error=>{
//                 res.json(error)
//             })
//         }
//     }
//     )
//     .catch((error)=>{
//         console.log(error);
//     })
// })

userRouter.post("/verifyOTP",async(req,res)=>{
    try{
       let {email,otp} = req.body;
       if(!otp){
        res.status(400).json({msg:"Empty otp details are not allowed"})
        // throw Error("Empty otp details are not allowed");
       }
        const userOtpVerificationRecords = await OtpVerificationModel.find({email});
        // if(userOtpVerificationRecords.length <= 0){
        //     res.json({msg:"Record doesn't exist !, Please signup again"})
        //     // throw "Record doesn't exist !, Please signup again"
        // }
            const {expiresAt} = userOtpVerificationRecords[0];
            const hashedOtp = userOtpVerificationRecords[0].otp;
            if(expiresAt < Date.now()){
                await OtpVerificationModel.deleteMany({email})
                res.status(400).json({msg:"Code Expired"})
                // throw "Code has expired, please request again"
            }else{
               const validOtp = await bcrypt.compare(otp, hashedOtp)
               if(!validOtp){
                res.status(400).json({msg:"Worng otp"})
                
               }else{
                // await UserModel.updateOne({_id:userId},{verified:true})
               await OtpVerificationModel.deleteMany({email})
                res.status(200).json({msg:'User email verified successfully'})
               }
            }
        }
    catch(err){
        res.json({err});
    }
})




// Login
userRouter.post("/login",async(req,res)=>{
    const {email, password} = req.body;
    try{
       const user = await UserModel.findOne({email});
       if(user){
        bcrypt.compare(password,user.password,(err, result)=>{
            if(result){
                const token = jwt.sign({userId: user._id, user:user.name,username:user.name},process.env.accessSecret);
                // const refresh_token = jwt.sign({userID: user._id, user:user.name},"Prity");
                res.status(200).json({msg:"Login Successful", user,token});
                
            }else{
                res.status(400).json({msg:"Wrong email and password"})
            }
        })
       }
    }catch(err){
          res.json({err})
    }
})


userRouter.get("/logout",async(req,res)=>{
    const token = req.headers.authorization?.split(" ")[1];
   
    try{
    const blacklist = new BlacklistModel({token})
    await blacklist.save();
    res.status(200).json({msg:"User has been logges out"})
    }
    catch(err){
      res.status(400).json({err});
    }
})

userRouter.patch("/update/:userId", async (req, res) => {
  const userId= req.params.userId;
  const {name,email} = req.body;

  try {
    // const user = await UserModel.findById(userId);

    
      await UserModel.findByIdAndUpdate(userId, {name,email});
      res.status(200).json({ msg: "User has been updated" });
    } 
   catch (err) {
    res.status(400).json({ error: err });
  }
}
);

// noteRouter.patch("/update/:noteID",async(req,res)=>{
//   const {noteID} = req.params;
//   const payload = req.body;
//   try{
//     if(payload.userID === req.body.userID){
//       await NoteModel.findByIdAndUpdate({_id:noteID},payload);
//       res.status(200).json({msg:"Notes Updated"})
//     }
//   }catch(err){
//       res.status(400).json({err})
//   }
// })



module.exports = {
    userRouter
}