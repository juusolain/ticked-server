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
        success_url: 'https://ticked.jusola.xyz/back-from-stripe/success.html?session_id={CHECKOUT_SESSION_ID}',
        cancel_url: 'https://ticked.jusola.xyz/back-from-stripe/cancel.html'
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
        return_url: 'https://ticked.jusola.xyz/back-from-stripe/success.html',
      });
      return session.id
    } catch (error) {
      throw 'error.payments.manage'
    }
  }

  createCustomer = async (email) => {
    const customer = await this.stripe.customer.create({
      email: email
    })
    return customer
  }

  createSubscription = async (paymentMethodID, customerID) => {
    try {
      await this.stripe.paymentMethods.attach(paymentMethod, {
        customer: customerID
      })
    } catch (error) {
      console.warn(error)
      throw 'error.stripe.attachPaymentMethod'
    }

    await this.stripe.customers.update(
      customerID,
      {
        invoice_settings: {
          default_payment_method: paymentMethodID,
        },
      }
    );

    const subscription = await stripe.subscriptions.create({
      customer: req.body.customerId,
      items: [{ price: 'pro-yearly' }],
      expand: ['latest_invoice.payment_intent'],
    });
  }
}

export default Payments