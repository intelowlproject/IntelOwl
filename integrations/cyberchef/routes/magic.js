import { Router } from "express";
const router = Router();
import { magic } from "cyberchef/src/node/index.mjs";

/**
 * magicPost
 */
router.post("/", async function magicPost(req, res, next) {
    try {
        if (!req.body.input) {
            throw new TypeError("'input' property is required in request body");
        }

        const dish = await magic(req.body.input, req.body.args);
        res.send(dish);

    } catch (e) {
        next(e);
    }
});

export default router;
