import Stripe from 'stripe'

const base_url = process.env.NODE_ENV == "development" ? 'http://localhost:8080/' : 'https://ticked.jusola.xyz/'

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
        mode: 'subscription',
        success_url: base_url+'#/payments?from=checkout&cancel=false',
        cancel_url: base_url+'#/payments?from=checkout&cancel=true'
      });
      return session.id
    } catch (error) {
      console.error(error)
      throw 'error.payments.subscription'
    }
  }

  getBillingPortal = async (customerID) => {
    try {
      const session = await this.stripe.billingPortal.sessions.create({
        customer: customerID,
        return_url: base_url+'#/payments?from=portal',
      });
      console.log(session)
      return session.url 
    } catch (error) {
      console.error(error)
      throw 'error.payments.manage'
    }
  }

  newCustomer = async (userid) => {
    try {
      const customer = await this.stripe.customers.create({
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