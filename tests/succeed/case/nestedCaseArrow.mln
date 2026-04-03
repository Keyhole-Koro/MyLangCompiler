typedef struct {
    i32 v;
} Data;

Data d;
Data *p;

i32 main() {
    d.v = 5;
    p = &d;

    i32 x = 1;
    i32 res = case x of {
        1 -> (case p->v of { 5 -> 10; _ -> 0; });
        _ -> 0;
    };

    return res;
}
