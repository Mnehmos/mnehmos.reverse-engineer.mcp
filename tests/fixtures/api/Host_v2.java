package api;
public interface Host {
    String requiredName();
    default String optionalNote() { return "none"; }
    String addedLater();
}
