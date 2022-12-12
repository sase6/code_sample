const UserDB = require("../../database/controllers/User.js");
const Stripe = new (require("./StripeService.js"));
const Session = require("../controllers/session.js");
const encrypt = require("../encryption/index.js");
const { validateEmail } = require("../../misc/validator.js");
const { success, error } = require("../../misc/returnObj.js");

class UserService extends UserDB {
  constructor() {
    super();
    this.session = Session;
  }

  filterSensitiveUserData(user) {
    const sensitiveProps = ["password"];
    const result = {};
    for (let prop in user._doc) {
      const index = sensitiveProps.indexOf(prop);
      if (index === -1) result[prop] = user._doc[prop];
    }
    return result;
  }

  async signup(email, password) {
    try {
      if (!email || !password) return error("Missing parameter(s)");
      if (password.length < 6) return error("Password must be at least 6 characters long");

      const encryptedPassword = await encrypt.hash(password);
      const lowerCasedEmail = email.toLowerCase();
      const createUserResponse = await this.createUser({
        email: lowerCasedEmail,
        password: encryptedPassword
      });

      if (!createUserResponse.success) return error(createUserResponse.error);
      return success();

    } catch (internalError) {
      return error(internalError);
    }
  }

  login(email, password, sessionId) {
    try {
      if ((!email || !password) && !sessionId) return error("Missing parameter(s)");
      if (email && password) return this.loginByUserData(email, password);
      else return this.loginBySessionId(sessionId);
    } catch (internalError) {
      return error(internalError);
    }
  }

  async loginByUserData(email, password) {
    try {
      const findResponse = await this.find({email}, "");
      if (!findResponse.success) return error(findResponse.error);
      const user = findResponse.data[0];
      if (!user) return error(`Could not find user: ${email}`);
      const isPasswordCorrect = await encrypt.compare(password, user.password);
      if (!isPasswordCorrect) return error("Password is incorrect");
      const sessionId = await this.session.createNewSession(email);
      const userData = this.filterSensitiveUserData(user);
      return success({sessionId, userData: JSON.stringify(userData), method: "byUserData"});
    } catch (internalError) {
      return error(internalError);
    }
  }

  async loginBySessionId(sessionId) {
    try {
      const email = this.session.data[sessionId];
      if (!email) return error("Invalid sessionId");
      const findResponse = await this.find({email});
      if (!findResponse.success) return error(findResponse.error);
      const user = findResponse.data[0];
      if (!user) return error(`Could not find user ${email}`);
      const userData = this.filterSensitiveUserData(user);
      return success({userData: JSON.stringify(userData), method: "bySessionId"});
    } catch (internalError) {
      return error(internalError);
    }
  }

  async updateUserLocation(email, location) {
    try {
      if (!email || !location) return error("Missing parameter(s)");
      const response = await this.update({email, location});
      if (!response.success) return error(response.error);
      return success();
    } catch (internalError) {
      return error(internalError);
    }
  }

  async updateUserInsensitiveData(email, update) {
    try {
      if (!email || !update) return error("Missing parameter(s)");
      const insensitiveProps = ["firstName", "lastName", "profileBinary", "location", "isBarber", "phoneNumber", "favoriteBarber"];
      const userUpdate = {email};
      insensitiveProps.forEach(prop => {
        if (update[prop]) userUpdate[prop] = update[prop];
      });

      const findResponse = await this.find({email}, "email stripeAccountId");
      if (!findResponse.success) return error(findResponse.error);
      const foundUser = findResponse.data[0];
      if (!foundUser.email === email) return error("Database error");

      if (update.isBarber && !foundUser.stripeAccountId) {
        const stripeResponse = await Stripe.createAccount();
        if ((stripeResponse).success) {
          userUpdate.stripeAccountId = stripeResponse.data.id;
        }
      }
      const response = await this.update(userUpdate);
      if (!response.success) return error(response.update);
      return success(userUpdate);
    } catch (internalError) {
      return error(internalError);
    }
  }

  async getSearchedUsers(query) {
    try {
      if (!query) return error("Missing parameter(s)");
      const cases = {
        email: query,
        firstName: query,
        lastName: query
      };
      return (await this.findManyUsers(cases));
    } catch (internalError) {
      return error(internalError);
    }
  }

  signout(sessionId) {
    try {
      if (!sessionId) return error("Missing parameter(s)");
      delete this.session.data[sessionId];
      return success();
    } catch (internalError) {
      return error(internalError);
    }
  }

  async resetPassword(email, oldPassword, newPassword) {
    try {
      if (!email || !oldPassword || !newPassword) return error("Missing parameter(s)");
      const userResponse = await this.find({email}, "email password");
      if (!userResponse.success) return error(userResponse.error);
      const user = userResponse.data[0];
      if (!user) return error(`Cannot find user: ${email}`);
      if (user.email !== email) return error("Database error");
      const isPasswordCorrect = await encrypt.compare(oldPassword, user.password);
      if (!isPasswordCorrect) return error("Password is incorrect");
      const hashedNewPassword = await encrypt.hash(newPassword);
      const updateResponse = await this.update({email, password: hashedNewPassword});
      if (!updateResponse.success) return error(updateResponse.error);
      return success("done");

    } catch (internalError) {
      return error(internalError);
    }
  }

  async getPaymentHistory(email) {
    try {
      if (!email) return error("Missing parameter(s)");
      const response = await this.find({email}, "email paymentHistory");
      if (!response.success) return error(response.error);
      const user = response.data[0];
      if (!user) return error(`Cannot find user: ${email}`);
      if (user.email !== email) return error("Database error");
      return success(user.paymentHistory);
    } catch (internalError) {
      return error(internalError);
    }
  }

  async addToPaymentHistory(barberEmail, userEmail, listOfServices, costOfServices) {
    try {
      if (!barberEmail || !userEmail || !listOfServices || !costOfServices) return error("Missing parameter(s)");
      const date = new Date().toLocaleString();
      const id = `payment_history:${barberEmail}x${userEmail}x${date}x${(Math.random() * 100000).toFixed(4)}`;
      const paymentData = {
        id,
        date,
        amount: costOfServices,
        services: listOfServices
      };
      return (await this.updateArrayValue({
        filter: {email: userEmail},
        propName: "paymentHistory",
        value: paymentData,
        type: "insert"
      }));
    } catch (internalError) {
      return error(internalError);
    }
  }

  async getBlockedUsers(email) {
    try {
      if (!email) return error("Missing parameter(s)");
      const response = await this.find({email}, "email blockedUsers");
      if (response.error) return error(response.error);
      const user = response.data[0];
      if (!user) return error(`Cannot find user: ${email}`);
      if (user.email !== email) return error("Database error");
      return success(user.blockedUsers);
    } catch (internalError) {
      return error(internalError);
    }
  }

  async blockUser(email, blockedEmail) {
    try {
      if (!email || !blockedEmail) return error("Missing parameter(s)");
      return (await this.updateArrayValue({
        filter: {email},
        propName: "blockedUsers",
        type: "insert",
        value: blockedEmail
      }));
    } catch (internalError) {
      return error(internalError);
    }
  }

  async unblockUser(email, unblockedEmail) {
    try {
      if (!email || !unblockedEmail) return error("Missing parameter(s)");
      return (await this.updateArrayValue({
        filter: {email},
        propName: "blockedUsers",
        type: "delete",
        value: unblockedEmail
      }));
    } catch (internalError) {
      return error(internalError);
    }
  }

  async setFavoriteBarber(email, favoriteBarber) {
    try {
      if (!email || !favoriteBarber) return error("Missing parameter(s)");
      if (!validateEmail(favoriteBarber)) return error("Favorite barber must be a valid email");
      return this.updateUserInsensitiveData(email, {favoriteBarber});
    } catch (internalError) {
      return error(internalError);
    }
  };

  async createService(serviceData, email) {
    try {
      const {name, cost, time} = serviceData;
      if (!serviceData || !email || !name || !cost || !time) return error("Missing parameter(s)");

      // Find user 
      const findUserResponse = await this.find({email});
      if (!findUserResponse.success) return error(findUserResponse.error);
      let user = findUserResponse.data[0];
      if (!user) return error(`Cannot find user: ${email}`);

      // Verify user/ send verification link
      if (!user.stripeVerified) { 
        const account = (await Stripe.getAccount(user.stripeAccountId)).data;
        if (!account.charges_enabled) {
          const url = (await Stripe.getAccountLink(user.stripeAccountId)).data.url;
          return error(url);
        }
        
        await this.update({email, stripeVerified: true});
      }

      // Create new service
      const { id } = (await Stripe.createPrice(name, parseInt(cost * 100))).data; 
      await this.updateArrayValue({
        filter: {email},
        propName: "services",
        type: "insert",
        value: {...serviceData, stripePriceId: id}
      });

      return success({stripePriceId: id});
    } catch (internalError) {
      return error(internalError);
    }
  }

  async updateService(email, priceId, update) {
    try {
      if (!email, !priceId || !update) return error("Missing parameter(s)");
      const deleteServiceResponse = await this.deleteService(email, priceId);
      if (!deleteServiceResponse.success) return error(deleteServiceResponse.error);
      return this.createService(update, email);
    } catch (internalError) {
      return error(internalError);
    }
  }

  async deleteService(email, priceId) {
    try {
      if (!email || !priceId) return error("Missing parameter(s)");
      return await this.updateArrayValue({
        filter: {email},
        propName: "services",
        value: priceId
      });
    } catch (internalError) {
      return error(internalError);
    }
  }
}

module.exports = UserService;
