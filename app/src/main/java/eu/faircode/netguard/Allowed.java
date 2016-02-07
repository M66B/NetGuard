package eu.faircode.netguard;

public class Allowed {
    public String daddr;
    public int dport;

    public Allowed() {
        this.daddr = "test";
        this.dport = 80;
    }

    public Allowed(String daddr, int dport) {
        this.daddr = daddr;
        this.dport = dport;
    }
}
