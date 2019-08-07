let users = [
  'Second project!',
  {
    'id': 1,
    'Name': 'Adam',
    'Admin': true
  },
  {
    'id': 2,
    'Name': 'Paul',
    'Admin': true
  },
  {
    'id': 3,
    'Name': 'Steve',
    'Admin': true
  },
  {
    'id': 4,
    'Name': 'Gary',
    'Admin': true
  },
  {
    'id': 5,
    'Name': 'Test User'
  },
  {
    'id': 6,
    'Name': 'Test User 2'
  },
  {
    'id': 7,
    'Name': 'Test User 3'
  },
  {
    'id': 8,
    'Name': 'Test User 4'
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
exports.lambdaHandler = async (event, context) => {
  try {
    console.log('Received event:', JSON.stringify(event, null, 2));
    let responseBody = '';

    if (event.pathParameters && event.pathParameters.id) {
      responseBody = getUser(parseInt(event.pathParameters.id));
    } else {
      responseBody = getAllUsers();
    }

    return response = {
      statusCode: 200,
      body: JSON.stringify(responseBody),
      headers: {
        'Access-Control-Allow-Origin': '*'
      }
    }
  } catch (err) {
    console.log(err);
    return err;
  }
};

const getAllUsers = () => {
  return users;
};

const getUser = (id) => {
  let filteredUsers = users.filter(user => user.id === id);

  if (filteredUsers.length > 0) return filteredUsers

  return {
    'message': 'User not found!'
  };
};