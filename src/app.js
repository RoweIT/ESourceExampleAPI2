let users = [
  {
    id: 1,
    Name: 'Adam',
    Admin: true
  },
  {
    id: 2,
    Name: 'Paul',
    Admin: true
  },
  {
    id: 3,
    Name: 'Steve',
    Admin: true
  },
  {
    id: 4,
    Name: 'Gary',
    Admin: true
  },
  {
    id: 5,
    Name: 'Tim',
    Admin: true
  },
  {
    id: 99,
    Name: 'Joe',
    admin: false
  }
];
/**
 *
 * Event doc: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html#api-gateway-simple-proxy-for-lambda-input-format
 * @param {Object} event - API Gateway Lambda Proxy Input Format
 *
 * Context doc: https://docs.aws.amazon.com/lambda/latest/dg/nodejs-prog-model-context.html
 * @param {Object} context
 *
 * Return doc: https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-lambda-proxy-integrations.html
 * @returns {Object} object - API Gateway Lambda Proxy Output Format
 *
 */

let responseBody = {
  apiVersion: 2
};

exports.getAllUsers = async (event, context) => {
  try {
    console.log('Received event:', JSON.stringify(event, null, 2));
    responseBody.users = getAllUsers();

    return {
      statusCode: 200,
      body: JSON.stringify(responseBody),
      headers: {
        'Access-Control-Allow-Origin': '*'
      }
    };
  } catch (err) {
    return {
      statusCode: 401,
      body: {
        message: err.message
      },
      headers: {
        'Access-Control-Allow-Origin': '*'
      }
    };
  }
};

exports.getUser = async (event, context) => {
  try {
    console.log('Received event:', JSON.stringify(event, null, 2));
    responseBody.user = getUser(parseInt(event.pathParameters.id));

    return {
      statusCode: 200,
      body: JSON.stringify(responseBody),
      headers: {
        'Access-Control-Allow-Origin': '*'
      }
    };
  } catch (err) {
    return {
      statusCode: 401,
      body: {
        message: err.message
      },
      headers: {
        'Access-Control-Allow-Origin': '*'
      }
    };
  }
};

exports.createUser = async (event, context) => {
  try {
    console.log('Received event:', JSON.stringify(event, null, 2));
    let user = event.body;
    users.push(user);

    return {
      statusCode: 201,
      body: user,
      headers: {
        'Access-Control-Allow-Origin': '*'
      }
    };
  } catch (err) {
    return {
      statusCode: 401,
      body: {
        message: err.message
      },
      headers: {
        'Access-Control-Allow-Origin': '*'
      }
    };
  }
};

const getAllUsers = () => {
  return users;
};

const getUser = id => {
  let filteredUsers = users.filter(user => user.id === id);

  if (filteredUsers.length > 0) return filteredUsers;

  return {
    message: 'User not found!'
  };
};
