
self.addEventListener("install", event => {
console.log("installed")
})

self.addEventListener("fetch", event => {
event.respondWith(fetch(event.request))
})
