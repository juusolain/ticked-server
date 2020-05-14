import Stripe from 'stripe'


class Payments {
  constructor(STRIPE_KEY) {
    this.stripe = Stripe(STRIPE_KEY)
  }
  
  getSubscriptionCheckout = async (userid) =>{
    const session = await stripe.checkout.sessions.create({
      client_reference_id: userid,
      payment_method_types: ['card'],
      subscription_data: {
        items: [{
          plan: 'pro_yearly',
        }],
      },
      success_url: 'https://ticked.jusola.xyz/back-from-stripe/success.html?session_id={CHECKOUT_SESSION_ID}',
      cancel_url: 'https://ticked.jusola.xyz/back-from-stripe/cancel.html'
    });
    return session
  }

  getBillingPortal = async (customerID) => {
    const session = await stripe.billingPortal.sessions.create({
      customer: customerID,
      return_url: 'https://ticked.jusola.xyz/back-from-stripe/success.html',
    });
    return session
  }
}

export default Payments