import express from 'express';
import bodyParser from 'body-parser';

const app = express();
const port = 5656;

app.use(bodyParser.text());

app.post('/', (req, res) => {
    console.log(req.body);
    res.send('Request body logged');
});

app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});