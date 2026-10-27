const job = { title: "Test", desc: "Don't break" };
const jobJsonString = encodeURIComponent(JSON.stringify(job));
console.log(jobJsonString);
