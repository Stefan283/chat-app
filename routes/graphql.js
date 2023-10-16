const { GraphQLObjectType,
    GraphQLString,
    GraphQLInt,
    GraphQLNonNull,
    GraphQLSchema,
    GraphQLBoolean
} = require('graphql');

const { Messages, Users } = require('./Schema');
const { SidebarDataType, MessagesDataType } = require('./type')

const RootQueryType = new GraphQLObjectType({
    name: 'RootQuery',
    fields: {
        getSidebar: {
            type: SidebarDataType,
            args: {
                email: { type: GraphQLNonNull(GraphQLString) },
                jump: { type: GraphQLNonNull(GraphQLInt) },
            },
            resolve: async (_, { email, jump }) => {
                try {
                    const elementNumber = 20;
                    const messageDb = await Messages.findOne({ email });
                    if (!messageDb) {
                        return {
                            success: false,
                            message: 'User not found',
                        };
                    }

                    const result = await Messages.aggregate([
                        { $match: { email } },
                        { $unwind: '$conversations' },
                        { $sort: { 'conversations.messages.date': -1 } },
                        { $group: { _id: '$_id', conversations: { $push: '$conversations' } } },
                        { $project: { conversations: { $slice: ['$conversations', jump, elementNumber] } } },
                    ]);

                    const side = result[0]?.conversations?.map((conversation) => {
                        const last = conversation.messages.length - 1;
                        return {
                            username: conversation.username || '',
                            lastMsg: conversation.messages[last]?.message || '',
                            lastYou: conversation.messages[last]?.email === email,
                            date: conversation.messages[last]?.date || '0', // Default to '0' if date is missing
                            seen: conversation.seen || false,
                            avatar: conversation.avatar || '',
                            email: conversation.email || '',
                        };
                    });

                    const totalConversations = messageDb.conversations.length;
                    const hasMoreData = jump + elementNumber < totalConversations;

                    return {
                        success: true,
                        side: side || [],
                        hasMoreData,
                    };
                } catch (err) {
                    console.error(err);
                    throw new Error(err.message);
                }
            },
        },
        getMessages: {
            type: MessagesDataType,
            args: {
                email: { type: GraphQLNonNull(GraphQLString) },
                secondEmail: { type: GraphQLNonNull(GraphQLString) },
                jump: { type: GraphQLNonNull(GraphQLInt) }
            },
            resolve: async (_, { email, secondEmail, jump }) => {
                try {
                    const elementNumber = 50;
                    const messagesDb = await Messages.findOne({ email });
                    if (!messagesDb) {
                        return {
                            success: false,
                            message: 'User not found',
                        }
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
                            return {
                                success: true,
                                messages: reversedMessages || [],
                                avatar: nextMessages[0].avatar || '',
                                username: nextMessages[0].username || '',
                                hasMoreData: hasMoreData,
                                seen: nextMessages[0].seen || false,
                                bg: nextMessages[0].bg || ''
                            }
                        } else {
                            return {
                                success: false,
                                message: 'Conversation not found'
                            }
                        }
                    } else {
                        const userDb = await Users.findOne({ email: secondEmail });
                        if (userDb) {
                            return {
                                success: true,
                                messages: [],
                                avatar: userDb.avatar || '',
                                username: userDb.username,
                                hasMoreData: false,
                                seen: false,
                                bg: 'https://chatapp2834.s3.eu-west-3.amazonaws.com/p1.jpg'
                            }
                        } else {
                            return {
                                success: false,
                                message: "User don't exist"
                            }
                        }
                    }
                } catch (err) {
                    console.log(err);
                    throw new Error(err.message);
                }
            }
        }
    },
});

const RootMutationType = new GraphQLObjectType({
    name: 'RootMutation',
    fields: {
        changeBg: {
            type: GraphQLBoolean,
            args: {
                bg: { type: GraphQLNonNull(GraphQLString) },
                email: { type: GraphQLNonNull(GraphQLString) },
                emailSend: { type: GraphQLNonNull(GraphQLString) },
            },
            resolve: async (_, { bg, email, emailSend }) => {
                try {
                    const filter = { email: email };
                    const update = { $set: { 'conversations.$[conv].bg': bg } };
                    const options = { arrayFilters: [{ 'conv.email': emailSend }] };
                    const result = await Messages.updateOne(filter, update, options);
                    if (result.matchedCount === 1) {
                        return true;
                    } else return false
                } catch (err) {
                    console.log(err)
                    return false
                }
            }
        }
    }
})

module.exports = new GraphQLSchema({
    query: RootQueryType,
    mutation: RootMutationType
});