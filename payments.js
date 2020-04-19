import stripe from 'stripe'

class Payments {
    getSubscriptionCheckout = async () =>{
        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'],
            subscription_data: {
              items: [{
                plan: 'tickedpro_yearly',
              }],
            }
        });
        return session
    }
}

export default Payments