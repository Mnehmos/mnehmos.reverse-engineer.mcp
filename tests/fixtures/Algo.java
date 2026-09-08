public class Algo {
    private int counter;
    static final int MASK = 0x5bf03635;

    public int sumEven(int[] xs) {
        int total = 0;
        for (int i = 0; i < xs.length; i++) {
            if (xs[i] % 2 == 0) {
                total += xs[i];
            }
        }
        return total;
    }

    public String describe(String name, int n) {
        return "item " + name + " count=" + n;
    }

    public int hashOf(String s) {
        int h = 0;
        for (int i = 0; i < s.length(); i++) {
            h = h * 31 + s.charAt(i);
            h ^= MASK;
        }
        return h;
    }

    public String classify(int v) {
        switch (v) {
            case 1: return "one";
            case 2: return "two";
            case 7: return "seven";
            default: return "other";
        }
    }

    public int safeDiv(int a, int b) {
        try {
            return a / b;
        } catch (ArithmeticException e) {
            return -1;
        }
    }

    public void bump() {
        this.counter++;
    }
}
