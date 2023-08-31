var express = require('express');
var router = express.Router();
const { Messages, Users } = require("./Schema");






router.post('/sidebar', async (req, res) => {
    const { email, jump } = req.body
    try {

        const elementNumber = 20;
        const messageDb = await Messages.findOne({ email });
        if (!messageDb) {
            return res.json({ success: false, message: 'User not found' });
        }
        const result = await Messages.aggregate([
            { $match: { email } },
            { $unwind: "$conversations" },
            { $sort: { "conversations.messages.date": -1 } },
            { $group: { _id: "$_id", conversations: { $push: "$conversations" } } },
            { $project: { conversations: { $slice: ["$conversations", jump, elementNumber] } } }
        ]);

        const side = result[0]?.conversations?.map((conversation) => {
            const last = conversation.messages.length - 1
            return {
                username: conversation.username || '',
                lastMsg: conversation.messages[last]?.message || '',
                lastYou: conversation.messages[last]?.email === email,
                date: conversation.messages[last]?.date || 0,
                seen: conversation.seen || false,
                avatar: conversation.avatar || '',
                email: conversation.email || ''
            }
        });
        const totalConversations = messageDb.conversations.length
        const hasMoreData = jump + elementNumber < totalConversations
        res.json({ success: true, side: side || [], hasMoreData: hasMoreData });
    } catch (err) {
        console.log(err)
        res.json({ success: false, message: err.message })
    }
})

router.post(`/messages`, async (req, res) => {
    const { email, secondEmail, jump } = req.body;
    try {
        const elementNumber = 50;
        const messagesDb = await Messages.findOne({ email });
        if (!messagesDb) {
            return res.json({ success: false, message: 'User not found' });
        }
        const messages = messagesDb?.conversations?.find(conversation => {
            return conversation.email === secondEmail;
        });
        if (messages) {
            const nextMessages = await Messages.aggregate([
                { $match: { email } },
                { $unwind: '$conversations' },
                { $match: { 'conversations.email': secondEmail } },
                {
                    $project: {
                        _id: 0,
                        messages: '$conversations.messages',
                        avatar: '$conversations.avatar',
                        username: '$conversations.username',
                        seen: '$conversations.seen',
                        bg: '$conversations.bg'
                    }
                },
                { $limit: 1 },
                {
                    $project: {
                        messages: {
                            $slice: [
                                { $reverseArray: '$messages' },
                                jump,
                                elementNumber
                            ]
                        },
                        avatar: 1,
                        username: 1,
                        seen: 1,
                        bg: 1,
                    }
                }
            ]);
            if (nextMessages.length > 0) {
                const reversedMessages = nextMessages[0].messages;
                const hasMoreData = reversedMessages.length === elementNumber ? true : false
                console.log()
                res.json({
                    success: true,
                    messages: reversedMessages || [],
                    avatar: nextMessages[0].avatar || '',
                    username: nextMessages[0].username || '',
                    hasMoreData: hasMoreData,
                    seen: nextMessages[0].seen || false,
                    bg: nextMessages[0].bg || ''
                });
            } else {
                res.json({ success: false, message: 'Conversation not found' });
            }
        } else {
            const userDb = await Users.findOne({ email: secondEmail });
            if (userDb) {
                res.json({
                    success: true,
                    messages: [],
                    avatar: userDb.avatar || '',
                    username: userDb.name,
                    hasMoreData: false,
                    seen: false,
                    bg: 'https://chatapp2834.s3.eu-west-3.amazonaws.com/p1.jpg'
                });
            } else {
                res.json({ success: false, message: 'User don\'t exist' });
            }
        }
    } catch (err) {
        console.log(err);
        res.json({ success: false, message: err.message });
    }
});


router.post(`/background`, async (req, res) => {
    const { bg, email, emailSend } = req.body
    try {
        const filter = { email: email };
        const update = { $set: { 'conversations.$[conv].bg': bg } };
        const options = { arrayFilters: [{ 'conv.email': emailSend }] };

        await Messages.updateOne(filter, update, options);

        res.json({ success: true })
    } catch (err) {
        console.log(err)
        res.json({ success: false, message: err })
    }
})

module.exports = router;
