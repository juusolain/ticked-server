import Stripe from 'stripe'


class Payments {
  constructor(STRIPE_KEY) {
    this.stripe = Stripe(STRIPE_KEY)
  }
  
  getSubscriptionCheckout = async (userid) =>{
    try {
      const session = await this.stripe.checkout.sessions.create({
        client_reference_id: userid,
        payment_method_types: ['card'],
        metadata: {
          userid: userid
        },
        subscription_data: {
          items: [{
            plan: 'pro-yearly',
          }],
        },
        success_url: 'https://ticked.jusola.xyz/#/payments/success',
        cancel_url: 'https://ticked.jusola.xyz/#/payments/cancel'
      });
      return session.id
    } catch (error) {
      throw 'error.payments.subscription'
    }
  }

  getBillingPortal = async (customerID) => {
    try {
      const session = await this.stripe.billingPortal.sessions.create({
        customer: customerID,
        return_url: 'https://ticked.jusola.xyz/#/payments/return',
      });
      return session.id
    } catch (error) {
      throw 'error.payments.manage'
    }
  }
}

export default Payments