const { GraphQLObjectType,
    GraphQLString,
    GraphQLBoolean,
    GraphQLList,
    GraphQLScalarType
} = require('graphql');

const BigIntType = new GraphQLScalarType({
    name: 'BigInt',
    description: 'A custom scalar type representing a BigInt',
    parseValue: (value) => BigInt(value),
});

const SideMessageType = new GraphQLObjectType({
    name: 'SideMessage',
    fields: {
        username: { type: GraphQLString },
        lastMsg: { type: GraphQLString },
        lastYou: { type: GraphQLBoolean },
        date: { type: GraphQLString },
        seen: { type: GraphQLBoolean },
        avatar: { type: GraphQLString },
        email: { type: GraphQLString },
    },
});

const SidebarDataType = new GraphQLObjectType({
    name: 'SidebarData',
    fields: {
        success: { type: GraphQLBoolean },
        side: { type: GraphQLList(SideMessageType) },
        hasMoreData: { type: GraphQLBoolean },
        message: { type: GraphQLString }
    },
});

const MessagesType = new GraphQLObjectType({
    name: 'Messages',
    fields: {
        message: { type: GraphQLString },
        date: { type: BigIntType },
        email: { type: GraphQLString },
        photo: { type: GraphQLString }
    }
})

const MessagesDataType = new GraphQLObjectType({
    name: 'MessagesData',
    fields: {
        success: { type: GraphQLBoolean },
        messages: { type: GraphQLList(MessagesType) },
        message: { type: GraphQLString },
        avatar: { type: GraphQLString },
        username: { type: GraphQLString },
        hasMoreData: { type: GraphQLBoolean },
        seen: { type: GraphQLBoolean },
        bg: { type: GraphQLString }
    }
})

module.exports = {
    SidebarDataType,
    MessagesDataType
}