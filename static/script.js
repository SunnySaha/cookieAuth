var createCheckoutSession = function(amount) {
    return fetch("/create-payment-session", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        amount: amount
      })
    }).then(function(result) {
      return result.json();
    });
  };

const stripe = Stripe("pk_test_51KZ81bHdxycVYLX5Yjcqa4JYJOx2LkgQwJkgBodbJD7RuHa9IXJf4YpMkPx3o6Flzf1wx0f4lFwrdOuYpV9Tubyp00HZSvBXjq")

document.addEventListener("DOMContentLoaded", function(event) {
    document
    .getElementById("payment")
    .addEventListener("click", function(evt) {
        createCheckoutSession(1235).then(function(data) {
           var elements = stripe.elements();
           var cardElement = elements.create('card')
           cardElement.mount("#card-element")
                          stripe
  .confirmCardPayment(data.paymentIntent, {
    payment_method: {
      card: {
        card_number: '4242424242424242',
        cardCvc: 452,
        cardExpiry: 2023
      },
    },
  })
  .then(function(result) {
    // Handle result.error or result.paymentIntent
  });
            });
        });

})
