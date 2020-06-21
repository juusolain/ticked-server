import Stripe from 'stripe'


class Payments {
  constructor(STRIPE_KEY) {
    this.stripe = Stripe(STRIPE_KEY)
  }
  
  getSubscriptionCheckout = async (userid, customerid) =>{
    try {
      const session = await this.stripe.checkout.sessions.create({
        client_reference_id: userid,
        customer: customerid,
        payment_method_types: ['card'],
        metadata: {
          userid: userid
        },
        line_items: [
          {
            price: 'pro-yearly',
            quantity:  1
          }
        ],
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
      return session.url
    } catch (error) {
      throw 'error.payments.manage'
    }
  }

  newCustomer = async (userid) => {
    try {
      const customer = await stripe.customers.create({
        metadata: {
          userid
        }
      })
      return customer.id
    } catch (error) {
      console.error(error)
    }
  }
}

export default Payments